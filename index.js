const { EventEmitter } = require('events');
const { Buffer } = require('buffer');
const ObservableStore = require('obs-store');
const { normalize: normalizeAddress } = require('eth-sig-util');

const WhaleKeyring = require('pentagonxyz/whale-keyring');

const keyringTypes = [WhaleKeyring];

const KEYRINGS_TYPE_MAP = {
  WHALE_KEYRING: 'Waymont Co. SCW',
};

class KeyringController extends EventEmitter {
  //
  // PUBLIC METHODS
  //

  constructor(opts) {
    super();
    const initState = opts.initState || {};
    this.keyringTypes = keyringTypes;
    this.store = new ObservableStore(initState);
    this.memStore = new ObservableStore({
      isUnlocked: false,
      keyringTypes: this.keyringTypes.map((krt) => krt.type),
      keyrings: [],
    });

    this.keyrings = [];
    this.baseAppUrl = opts.baseAppUrl;
    this.baseApiUrl = opts.baseApiUrl;
    this.processTransaction = opts.processTransaction;
  }

  /**
   * Full Update
   *
   * Emits the `update` event and @returns a Promise that resolves to
   * the current state.
   *
   * Frequently used to end asynchronous chains in this class,
   * indicating consumers can often either listen for updates,
   * or accept a state-resolving promise to consume their results.
   *
   * @returns {Object} The controller state.
   */
  fullUpdate() {
    this.emit('update', this.memStore.getState());
    return this.memStore.getState();
  }

  /**
   * Create New Vault And Keychain
   *
   * Destroys any old encrypted storage,
   * creates a new encrypted store with the given accessToken,
   * randomly creates a new HD wallet with 1 account,
   * faucets that account on the testnet.
   *
   * @emits KeyringController#unlock
   * @param {string} accessToken - The accessToken used for signing transactions.
   * @returns {Promise<Object>} A Promise that resolves to the state.
   */
  async createNewVaultAndKeychain(accessToken) {
    this.store.updateState({ vault: "WAYMONT_CO_SCW" });
    if (accessToken !== undefined && typeof accessToken === 'string' && accessToken.length > 0) {
      await this.createFirstKeyTree(accessToken);
      this.setUnlocked.bind();
    }
    this.fullUpdate();
  }

  /**
   * CreateNewVaultAndRestore
   *
   * Destroys any old encrypted storage,
   * creates a new encrypted store with the given password,
   * creates a new HD wallet from the given seed with 1 account.
   *
   * @emits KeyringController#unlock
   * @param {string} password - The password to encrypt the vault with
   * @param {string|Array<number>} seedPhrase - The BIP39-compliant seed phrase,
   * either as a string or an array of UTF-8 bytes that represent the string.
   * @returns {Promise<Object>} A Promise that resolves to the state.
   */
  async createNewVaultAndRestore(password, seedPhrase) {
    throw new Error("createNewVaultAndRestore is not implemented in Waymont Co.'s KeyringController.");
  }

  /**
   * Set Locked
   * This method deallocates all secrets, and effectively locks MetaMask.
   *
   * @emits KeyringController#lock
   * @returns {Promise<Object>} A Promise that resolves to the state.
   */
  async setLocked(isLoggedOutAlready) {
    // set locked
    this.accessToken = null;
    if (!isLoggedOutAlready) this.getKeyringsByType(KEYRINGS_TYPE_MAP.WHALE_KEYRING)[0].logout();
    this.memStore.updateState({ isUnlocked: false });
    // remove keyrings
    this.keyrings = [];
    await this._updateMemStoreKeyrings();
    this.emit('lock');
    return this.fullUpdate();
  }

  /**
   * Submit Access Token (still named `submitPassword` though)
   *
   * Attempts to access the current vault and load its keyrings
   * into memory.
   *
   * Temporarily also migrates any old-style vaults first, as well.
   * (Pre MetaMask 3.0.0)
   *
   * @emits KeyringController#unlock
   * @param {string} accessToken - The keyring controller access token.
   * @returns {Promise<Object>} A Promise that resolves to the state.
   */
  async submitPassword(accessToken) {
    this.keyrings = await this.unlockKeyrings(accessToken);
    this.setUnlocked();
    this.fullUpdate();
  }

  /**
   * Verify Access Token (still named `verifyPassword` though)
   *
   * Attempts to access the current vault with a given Access Token
   * to verify its validity.
   *
   * @param {string} accessToken
   */
  async verifyPassword(accessToken) {
    throw new Error("verifyPassword is not implemented in Waymont Co.'s KeyringController.");
  }

  /**
   * Add New Keyring
   *
   * Adds a new Keyring of the given `type` to the vault
   * and the current decrypted Keyrings array.
   *
   * All Keyring classes implement a unique `type` string,
   * and this is used to retrieve them from the keyringTypes array.
   *
   * @param {string} type - The type of keyring to add.
   * @param {Object} accessToken - The accessToken for the keyring.
   * @returns {Promise<Keyring>} The new keyring.
   */
  async addNewKeyring(type, accessToken) {
    if (type !== KEYRINGS_TYPE_MAP.WHALE_KEYRING) throw "Only KEYRINGS_TYPE_MAP.WHALE_KEYRING is supposed by Waymont Co.'s KeyringController.";
    if (this.getKeyringsByType(KEYRINGS_TYPE_MAP.WHALE_KEYRING).length > 0) throw "Keyring already added.";

    const Keyring = this.getKeyringClassForType(type);
    const keyring = new Keyring(accessToken, this.baseAppUrl, this.baseApiUrl, this.setLocked);
    keyring.forceNextMfaSetup = this.forceNextMfaSetup;
    this.forceNextMfaSetup = false;

    if (this.getKeyringsByType(KEYRINGS_TYPE_MAP.WHALE_KEYRING).length > 0) throw "Keyring already added.";
    let accounts = await this.getKeyringAccounts(keyring);
    if (accounts.length == 0) {
      if (this.getKeyringsByType(KEYRINGS_TYPE_MAP.WHALE_KEYRING).length > 0) throw "Keyring already added.";
      if (!(await keyring.checkMfaStatus())) {
        if (this.getKeyringsByType(KEYRINGS_TYPE_MAP.WHALE_KEYRING).length > 0) throw "Keyring already added.";
        await keyring.waitForMfaSetup();
      }
      if (this.getKeyringsByType(KEYRINGS_TYPE_MAP.WHALE_KEYRING).length > 0) throw "Keyring already added.";
      accounts = await keyring.addAccounts();
    }

    if (this.getKeyringsByType(KEYRINGS_TYPE_MAP.WHALE_KEYRING).length > 0) throw "Keyring already added.";
    this.keyrings.push(keyring);

    await this._updateMemStoreKeyrings();
    this.fullUpdate();

    return keyring;
  }

  /**
   * Remove Empty Keyrings
   *
   * Loops through the keyrings and removes the ones with empty accounts
   * (usually after removing the last / only account) from a keyring
   */
  async removeEmptyKeyrings() {
    const validKeyrings = [];

    // Since getAccounts returns a Promise
    // We need to wait to hear back form each keyring
    // in order to decide which ones are now valid (accounts.length > 0)

    await Promise.all(
      this.keyrings.map(async (keyring) => {
        const accounts = await this.getKeyringAccounts(keyring);
        if (accounts.length > 0) {
          validKeyrings.push(keyring);
        }
      }),
    );
    this.keyrings = validKeyrings;
  }

  /**
   * Add New Account
   *
   * Calls the `addAccounts` method on the given keyring,
   * and then saves those changes.
   *
   * @param {Keyring} selectedKeyring - The currently selected keyring.
   * @returns {Promise<Object>} A Promise that resolves to the state.
   */
  async addNewAccount(selectedKeyring, name) {
    const accounts = await selectedKeyring.addAccounts(1, name !== undefined && typeof name === 'string' && name.length > 0 ? [name] : undefined);
    accounts.forEach((hexAccount) => {
      this.emit('newAccount', hexAccount);
    });

    await this._updateMemStoreKeyrings();
    this.fullUpdate();
  }

  renameAccount(address, name) {
    return this.getKeyringsByType(KEYRINGS_TYPE_MAP.WHALE_KEYRING)[0].renameAccount(address, name);
  }

  /**
   * Export Account
   *
   * Requests the private key from the keyring controlling
   * the specified address.
   *
   * Returns a Promise that may resolve with the private key string.
   *
   * @param {string} address - The address of the account to export.
   * @returns {Promise<string>} The private key of the account.
   */
  async exportAccount(address) {
    const keyring = await this.getKeyringForAccount(address);
    return await keyring.exportAccount(normalizeAddress(address));
  }

  /**
   *
   * Remove Account
   *
   * Removes a specific account from a keyring
   * If the account is the last/only one then it also removes the keyring.
   *
   * @param {string} address - The address of the account to remove.
   * @returns {Promise<void>} A Promise that resolves if the operation was successful.
   */
  async removeAccount(address) {
    const keyring = await this.getKeyringForAccount(address);

    // Not all the keyrings support this, so we have to check
    if (typeof keyring.removeAccount === 'function') {
      keyring.removeAccount(address);
      this.emit('removedAccount', address);
    } else {
      throw new Error(
        `Keyring ${keyring.type} doesn't support account removal operations`,
      );
    }

    const accounts = await this.getKeyringAccounts(keyring);
    // Check if this was the last/only account
    if (accounts.length === 0) {
      await this.removeEmptyKeyrings();
    }

    await this._updateMemStoreKeyrings();
    this.fullUpdate();
  }

  //
  // SIGNING METHODS
  //

  /**
   * Sign Ethereum Transaction
   *
   * Signs an Ethereum transaction object.
   *
   * @param {Object} ethTx - The transaction to sign.
   * @param {string} _fromAddress - The transaction 'from' address.
   * @param {Object} opts - Signing options.
   * @returns {Promise<string>} The submitted transaction hash.
   */
  async sendTransaction(ethTx, _fromAddress, opts = {}) {
    const fromAddress = normalizeAddress(_fromAddress);
    const keyring = await this.getKeyringForAccount(fromAddress);
    return await keyring.sendTransaction(fromAddress, ethTx, opts);
  }

  /**
   * Sign Message
   *
   * Attempts to sign the provided message parameters.
   *
   * @param {Object} msgParams - The message parameters to sign.
   * @returns {Promise<Buffer>} The raw signature.
   */
  async signMessage(msgParams, opts = {}) {
    const address = normalizeAddress(msgParams.from);
    const keyring = await this.getKeyringForAccount(address);
    return await keyring.signMessage(address, msgParams.data, opts);
  }

  /**
   * Sign Personal Message
   *
   * Attempts to sign the provided message parameters.
   * Prefixes the hash before signing per the personal sign expectation.
   *
   * @param {Object} msgParams - The message parameters to sign.
   * @returns {Promise<Buffer>} The raw signature.
   */
  async signPersonalMessage(msgParams, opts = {}, origin) {
    const address = normalizeAddress(msgParams.from);
    const keyring = await this.getKeyringForAccount(address);
    return await keyring.signPersonalMessage(address, msgParams.data, opts, this.processTransaction, origin);
  }

  /**
   * Get encryption public key
   *
   * Get encryption public key for using in encrypt/decrypt process.
   *
   * @param {Object} address - The address to get the encryption public key for.
   * @returns {Promise<Buffer>} The public key.
   */
  async getEncryptionPublicKey(_address, opts = {}) {
    const address = normalizeAddress(_address);
    const keyring = await this.getKeyringForAccount(address);
    return await keyring.getEncryptionPublicKey(address, opts);
  }

  /**
   * Decrypt Message
   *
   * Attempts to decrypt the provided message parameters.
   *
   * @param {Object} msgParams - The decryption message parameters.
   * @returns {Promise<Buffer>} The raw decryption result.
   */
  async decryptMessage(msgParams, opts = {}) {
    const address = normalizeAddress(msgParams.from);
    const keyring = await this.getKeyringForAccount(address);
    return keyring.decryptMessage(address, msgParams.data, opts);
  }

  /**
   * Sign Typed Data
   * (EIP712 https://github.com/ethereum/EIPs/pull/712#issuecomment-329988454)
   *
   * @param {Object} msgParams - The message parameters to sign.
   * @returns {Promise<Buffer>} The raw signature.
   */
  async signTypedMessage(msgParams, opts = { version: 'V1' }) {
    const address = normalizeAddress(msgParams.from);
    const keyring = await this.getKeyringForAccount(address);
    return keyring.signTypedData(address, msgParams.data, opts);
  }

  /**
   * Gets the app key address for the given Ethereum address and origin.
   *
   * @param {string} _address - The Ethereum address for the app key.
   * @param {string} origin - The origin for the app key.
   * @returns {string} The app key address.
   */
  async getAppKeyAddress(_address, origin) {
    const address = normalizeAddress(_address);
    const keyring = await this.getKeyringForAccount(address);
    return keyring.getAppKeyAddress(address, origin);
  }

  /**
   * Exports an app key private key for the given Ethereum address and origin.
   *
   * @param {string} _address - The Ethereum address for the app key.
   * @param {string} origin - The origin for the app key.
   * @returns {string} The app key private key.
   */
  async exportAppKeyForAddress(_address, origin) {
    const address = normalizeAddress(_address);
    const keyring = await this.getKeyringForAccount(address);
    if (!('exportAccount' in keyring)) {
      throw new Error(
        `The keyring for address ${_address} does not support exporting.`,
      );
    }
    return keyring.exportAccount(address, { withAppKeyOrigin: origin });
  }

  //
  // PRIVATE METHODS
  //

  /**
   * Create First Key Tree
   *
   * - Clears the existing vault
   * - Creates a new vault
   * - Creates a random new HD Keyring with 1 account
   * - Makes that account the selected account
   * - Faucets that account on testnet
   * - Puts the current seed words into the state tree
   *
   * @param {string} accessToken - The keyring controller access token.
   * @returns {Promise<void>} - A promise that resolves if the operation was successful.
   */
  async createFirstKeyTree(accessToken) {
    this.accessToken = accessToken;
    this.clearKeyrings();

    const keyring = await this.addNewKeyring(KEYRINGS_TYPE_MAP.WHALE_KEYRING);
    const [firstAccount] = await this.getKeyringAccounts(keyring);
    if (!firstAccount) {
      throw new Error('KeyringController - No account found on keychain.');
    }

    const hexAccount = normalizeAddress(firstAccount);
    this.emit('newVault', hexAccount);
    return null;
  }

  /**
   * Unlock Keyrings
   *
   * Attempts to unlock the persisted encrypted storage,
   * initializing the persisted keyrings to RAM.
   *
   * @param {string} accessToken - The keyring controller accessToken.
   * @returns {Promise<Array<Keyring>>} The keyrings.
   */
  async unlockKeyrings(accessToken) {
    await this.clearKeyrings();
    this.accessToken = accessToken;
    await this._restoreKeyring({ type: KEYRINGS_TYPE_MAP.WHALE_KEYRING, data: accessToken });
    await this._updateMemStoreKeyrings();
    return this.keyrings;
  }

  /**
   * Restore Keyring
   *
   * Attempts to initialize a new keyring from the provided serialized payload.
   * On success, updates the memStore keyrings and returns the resulting
   * keyring instance.
   *
   * @param {Object} serialized - The serialized keyring.
   * @returns {Promise<Keyring>} The deserialized keyring.
   */
  async restoreKeyring(serialized) {
    const keyring = await this._restoreKeyring(serialized);
    await this._updateMemStoreKeyrings();
    return keyring;
  }

  /**
   * Restore Keyring Helper
   *
   * Attempts to initialize a new keyring from the provided serialized payload.
   * On success, returns the resulting keyring instance.
   *
   * @param {Object} serialized - The serialized keyring.
   * @returns {Promise<Keyring>} The deserialized keyring.
   */
  async _restoreKeyring(serialized) {
    const { type, data } = serialized;
    if (type === KEYRINGS_TYPE_MAP.WHALE_KEYRING && this.getKeyringsByType(KEYRINGS_TYPE_MAP.WHALE_KEYRING).length > 0) throw "Keyring already added.";

    const Keyring = this.getKeyringClassForType(type);
    const keyring = new Keyring(undefined, this.baseAppUrl, this.baseApiUrl, this.setLocked);
    keyring.forceNextMfaSetup = this.forceNextMfaSetup;
    this.forceNextMfaSetup = false;
    await keyring.deserialize(data);
    // getAccounts also validates the accounts for some keyrings
    if (type === KEYRINGS_TYPE_MAP.WHALE_KEYRING && this.getKeyringsByType(KEYRINGS_TYPE_MAP.WHALE_KEYRING).length > 0) throw "Keyring already added.";
    let accounts = await this.getKeyringAccounts(keyring);
    if (type === KEYRINGS_TYPE_MAP.WHALE_KEYRING && accounts.length == 0) {
      if (this.getKeyringsByType(KEYRINGS_TYPE_MAP.WHALE_KEYRING).length > 0) throw "Keyring already added.";
      if (!(await keyring.checkMfaStatus())) {
        if (this.getKeyringsByType(KEYRINGS_TYPE_MAP.WHALE_KEYRING).length > 0) throw "Keyring already added.";
        await keyring.waitForMfaSetup();
      }
      if (this.getKeyringsByType(KEYRINGS_TYPE_MAP.WHALE_KEYRING).length > 0) throw "Keyring already added.";
      accounts = await keyring.addAccounts();
    }
    if (type === KEYRINGS_TYPE_MAP.WHALE_KEYRING && this.getKeyringsByType(KEYRINGS_TYPE_MAP.WHALE_KEYRING).length > 0) throw "Keyring already added.";
    this.keyrings.push(keyring);
    return keyring;
  }

  /**
   * Get Keyring Class For Type
   *
   * Searches the current `keyringTypes` array
   * for a Keyring class whose unique `type` property
   * matches the provided `type`,
   * returning it if it exists.
   *
   * @param {string} type - The type whose class to get.
   * @returns {Keyring|undefined} The class, if it exists.
   */
  getKeyringClassForType(type) {
    return this.keyringTypes.find((kr) => kr.type === type);
  }

  /**
   * Get Keyrings by Type
   *
   * Gets all keyrings of the given type.
   *
   * @param {string} type - The keyring types to retrieve.
   * @returns {Array<Keyring>} The keyrings.
   */
  getKeyringsByType(type) {
    return this.keyrings.filter((keyring) => keyring.type === type);
  }

  /**
   * Get Accounts
   *
   * Returns the public addresses of all current accounts
   * managed by all currently unlocked keyrings.
   *
   * @returns {Promise<Array<string>>} The array of accounts.
   */
  async getAccounts() {
    const keyrings = this.keyrings || [];

    const keyringArrays = await Promise.all(
      keyrings.map((keyring) => keyring.getAccounts()),
    );
    const addresses = keyringArrays.reduce((res, arr) => {
      return res.concat(arr);
    }, []);

    return addresses.map(normalizeAddress);
  }

  /**
   * Get Account Names
   *
   * Returns the names of all current accounts
   * managed by WHALE_KEYRING.
   *
   * @returns {Promise<Object>} The object of account names indexed by account addresses.
   */
  getAccountNames() {
    return this.getKeyringsByType(KEYRINGS_TYPE_MAP.WHALE_KEYRING)[0].getAccountNames();
  }

  /**
   * Get Keyring For Account
   *
   * Returns the currently initialized keyring that manages
   * the specified `address` if one exists.
   *
   * @param {string} address - An account address.
   * @returns {Promise<Keyring>} The keyring of the account, if it exists.
   */
  async getKeyringForAccount(address) {
    const hexed = normalizeAddress(address);

    const candidates = await Promise.all(
      this.keyrings.map((keyring) => {
        return Promise.all([keyring, keyring.getAccounts()]);
      }),
    );

    const winners = candidates.filter((candidate) => {
      const accounts = candidate[1].map(normalizeAddress);
      return accounts.includes(hexed);
    });
    if (winners && winners.length > 0) {
      return winners[0][0];
    }

    // Adding more info to the error
    let errorInfo = '';
    if (!address) {
      errorInfo = 'The address passed in is invalid/empty';
    } else if (!candidates || !candidates.length) {
      errorInfo = 'There are no keyrings';
    } else if (!winners || !winners.length) {
      errorInfo = 'There are keyrings, but none match the address';
    }
    throw new Error(
      `No keyring found for the requested account. Error info: ${errorInfo}`,
    );
  }

  /**
   * Display For Keyring
   *
   * Is used for adding the current keyrings to the state object.
   * @param {Keyring} keyring
   * @returns {Promise<Object>} A keyring display object, with type and accounts properties.
   */
  async displayForKeyring(keyring) {
    const accounts = await this.getKeyringAccounts(keyring);

    return {
      type: keyring.type,
      accounts: accounts.map(normalizeAddress),
    };
  }

  /**
   * Clear Keyrings
   *
   * Deallocates all currently managed keyrings and accounts.
   * Used before initializing a new vault.
   */

  /* eslint-disable require-await */
  async clearKeyrings() {
    // clear keyrings from memory
    this.keyrings = [];
    this.memStore.updateState({
      keyrings: [],
    });
  }

  /**
   * Update memStore Keyrings
   *
   * Updates the in-memory keyrings, without persisting.
   */
  async _updateMemStoreKeyrings() {
    const keyrings = await Promise.all(
      this.keyrings.map(this.displayForKeyring.bind(this)),
    );
    return this.memStore.updateState({ keyrings });
  }

  /**
   * Unlock Keyrings
   *
   * Unlocks the keyrings.
   *
   * @emits KeyringController#unlock
   */
  setUnlocked() {
    this.memStore.updateState({ isUnlocked: true });
    this.emit('unlock');
  }

  /**
   * Forget hardware keyring
   *
   * Forget hardware and update memorized state.
   * @param {Keyring} keyring
   */
  forgetKeyring(keyring) {
    if (keyring.forgetDevice) {
      keyring.forgetDevice();
      this._updateMemStoreKeyrings.bind(this)();
    } else {
      throw new Error(
        `KeyringController - keyring does not have method "forgetDevice", keyring type: ${keyring.type}`,
      );
    }
  }

  mfaResolution(signatureData, errorMessage) {
    return this.getKeyringsByType(KEYRINGS_TYPE_MAP.WHALE_KEYRING)[0].mfaResolution(signatureData, errorMessage);
  }

  async getKeyringAccounts(keyring) {
    try {
      return await keyring.getAccounts();
    } catch (err) {
      // Check for expired access token; if so, throw error to be caught by KeyringController, who will call setLocked()
      if (err.toString().indexOf("Expected Iterable, but did not find one for field \"Query.wallets\".") >= 0) {
        this.setLocked(true);
        throw "Logged out...";
      }
      throw err;
    }
  }
}

module.exports = KeyringController;
