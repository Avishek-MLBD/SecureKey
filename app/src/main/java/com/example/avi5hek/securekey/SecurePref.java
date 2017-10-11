package com.example.avi5hek.securekey;

import android.content.Context;
import android.os.Build;
import android.preference.PreferenceManager;
import android.security.KeyPairGeneratorSpec;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.util.Base64;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Calendar;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;

/**
 * Created by "Avishek" on 10/9/2017.
 */

public class SecurePref {

  private static final String AndroidKeyStore = "AndroidKeyStore";
  private static final String AES_MODE = "AES/GCM/NoPadding";
  private static final String RSA_MODE = "RSA/ECB/PKCS1Padding";
  private static final String KEY_ALIAS = "SecureKey";
  private static final String KEY_IV = "initializationVector";
  private static final String KEY_ENCRYPTED_AES = "AesKey";
  private static final String BLOCK_CIPHER_PROVIDER = "BC";
  private static final String ALGORITHM = "AES";

  private Context mContext;
  private KeyStore mKeyStore;
  private String mData;

  /**
   * Application context.
   *
   * @param context {@link Context} representing the application context.
   * @return {@link SecurePref}.
   */
  public static SecurePref with(Context context) {
    return new SecurePref(context);
  }

  SecurePref(Context context) {
    mContext = context;
    try {
      loadKeyStore();
    } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
      e.printStackTrace();
    }
  }

  /**
   * Loads keystore.
   */
  private void loadKeyStore()
      throws CertificateException, NoSuchAlgorithmException, IOException, KeyStoreException {
    mKeyStore = KeyStore.getInstance(AndroidKeyStore);
    mKeyStore.load(null);
  }

  /**
   * Encrypts the text passed as argument and stores in the shared preferences.
   *
   * @param key {@link String} representing the key of shared preferences.
   * @param text {@link String} to be encrypted and stored in the shared preferences.
   * @return {@link SecurePref}.
   */
  public SecurePref encrypt(String key, String text) {
    try {
      this.mData = getEncryptedText(text);
      storeInSharedPreferences(key, mData);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return this;
  }

  /**
   * Decrypts the encrypted text stored in the shared preferences.
   *
   * @param key {@link String} representing the key of shared preferences.
   * @return {@link SecurePref}.
   */
  public SecurePref decrypt(String key) {
    try {
      this.mData = getDecryptedText(getDataFromSharedPreferences(key));
    } catch (Exception e) {
      e.printStackTrace();
    }
    return this;
  }

  public String get() {
    return mData;
  }

  private String getEncryptedText(String text) throws Exception {
    // 1. Generate secret key. For version M and higher, get it from keystore. For versions lower than M, generate an AES key, encrypt it and store in the preferences.
    // 2. Initialize the block cipher using
    // 2.1. the secret key (for M and higher) from keystore or
    // 2.2. the decrypted AES key (for below M) stored in the preferences.
    // 3. Store the Initialization Vector (IV) in the preferences.
    // 4. Encrypt the data using block cipher.

    // To generate AES key:
    // 1.1. Generate RSA key pair.
    // 1.2. Generate a random AES key.
    // 1.3. Encrypt AES key using RSA public key.
    // 1.4. Store the encrypted AES in the preferences.
    Cipher cipher;
    // 2. Initialize the block cipher
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
      // 1. Generate secret key and store in the preferences.
      generateSecretKey();
      SecretKey secretKey = (SecretKey) mKeyStore.getKey(KEY_ALIAS, null);

      cipher = Cipher.getInstance(AES_MODE);
      // 2.1. using the secret key (for M and higher) from keystore.
      cipher.init(Cipher.ENCRYPT_MODE, secretKey);
    } else {
      // 1. Generate an AES key, encrypt it and store in the preferences.
      generateAesKey();
      cipher = Cipher.getInstance(AES_MODE, BLOCK_CIPHER_PROVIDER);
      // 2.2. using the decrypted AES key (for below M) stored in the preferences.
      cipher.init(Cipher.ENCRYPT_MODE, getSecretAesKey());
    }

    // 3. Store the Initialization Vector (IV) in the preferences.
    storeInSharedPreferences(KEY_IV, cipher.getIV());

    // 4. Encrypt the data using block cipher.
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, cipher);
    cipherOutputStream.write(text.getBytes("UTF-8"));
    cipherOutputStream.close();

    byte[] byteArray = outputStream.toByteArray();
    return (Base64.encodeToString(byteArray, Base64.DEFAULT));
  }

  /**
   * Generates a secret key in keystore.
   */
  @RequiresApi(api = Build.VERSION_CODES.M)
  private void generateSecretKey()
      throws NoSuchProviderException, NoSuchAlgorithmException, KeyStoreException,
      InvalidAlgorithmParameterException {
    if (mKeyStore != null && !mKeyStore.containsAlias(KEY_ALIAS)) {
      KeyGenerator keyGenerator =
          KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, AndroidKeyStore);
      keyGenerator.init(new KeyGenParameterSpec.Builder(KEY_ALIAS,
          KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT).setBlockModes(
          KeyProperties.BLOCK_MODE_GCM)
          .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
          .setRandomizedEncryptionRequired(false)
          .build());
      keyGenerator.generateKey(); // and that's how our secret key is generated
    }
  }

  /**
   * Generates an RSA key pair in keystore.
   */
  private void generateRsaKeyPair()
      throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException,
      InvalidAlgorithmParameterException {
    // Generate the RSA key pair
    if (!mKeyStore.containsAlias(KEY_ALIAS)) {
      // Generate a key pair for encryption
      Calendar start = Calendar.getInstance();
      Calendar end = Calendar.getInstance();
      end.add(Calendar.YEAR, 30);
      KeyPairGeneratorSpec spec =
          new KeyPairGeneratorSpec.Builder(mContext).setAlias(KEY_ALIAS)
              .setSubject(new X500Principal("CN=" + KEY_ALIAS))
              .setSerialNumber(BigInteger.TEN)
              .setStartDate(start.getTime())
              .setEndDate(end.getTime())
              .build();
      KeyPairGenerator kpg =
          KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, AndroidKeyStore);
      kpg.initialize(spec);
      kpg.generateKeyPair();
    }
  }

  /**
   * Randomly generates an AES key if not yet created and stored in the preferences.
   */
  private void generateAesKey() throws Exception {

    // 1.1 Generate RSA key pair.
    generateRsaKeyPair();
    // if no AES key is found in preferences, then create one and store it.
    if (getKeyFromSharedPreferences(KEY_ENCRYPTED_AES) == null) {
      // 1.2. Generate a random AES key.
      byte[] key = new byte[16];
      SecureRandom secureRandom = new SecureRandom();
      secureRandom.nextBytes(key);

      // 1.3. Encrypt AES key using the RSA public key.
      byte[] encryptedAesKey = rsaEncrypt(key);

      // 1.4. Store the encrypted AES in the preferences.
      storeInSharedPreferences(KEY_ENCRYPTED_AES, encryptedAesKey);
    }
  }

  /**
   * Retrieves the secret AES key.
   *
   * @return Byte array representing the AES key.
   */
  private Key getSecretAesKey() throws Exception {
    // retrieve the encrypted AES key from preferences and decrypt it.
    byte[] key = rsaDecrypt(getKeyFromSharedPreferences(KEY_ENCRYPTED_AES));
    return new SecretKeySpec(key, ALGORITHM);
  }

  /**
   * Stores any byte array in the preferences.
   *
   * @param key {@link String} representing the key of the key-value pair to be stored.
   * @param value A byte array representing the value of the key-value pair to be stored.
   */
  private void storeInSharedPreferences(String key, byte[] value) {
    storeInSharedPreferences(key, Base64.encodeToString(value, Base64.DEFAULT));
  }

  private void storeInSharedPreferences(String key, String value) {
    PreferenceManager.getDefaultSharedPreferences(mContext)
        .edit()
        .putString(key, value)
        .apply();
  }

  /**
   * Retrieves stored AES key or IV from the preferences.
   *
   * @param key {@link String} representing the key of the key-value pair stored in preferences.
   * @return Byte array representing the AES key or IV decoded from the preferences.
   */
  private byte[] getKeyFromSharedPreferences(String key) {
    String encryptedKeyBase64 = getDataFromSharedPreferences(key);
    return encryptedKeyBase64 != null ? Base64.decode(encryptedKeyBase64, Base64.DEFAULT) : null;
  }

  private String getDataFromSharedPreferences(String key) {
    return PreferenceManager.getDefaultSharedPreferences(mContext)
        .getString(key, null);
  }

  /**
   * Encrypts the secret AES key using the RSA public key in the keystore.
   *
   * @param secretAesKey {@link String} representing the randomly created AES key.
   * @return A byte array representing the encrypted AES.
   */
  private byte[] rsaEncrypt(byte[] secretAesKey) throws Exception {
    KeyStore.PrivateKeyEntry privateKeyEntry =
        (KeyStore.PrivateKeyEntry) mKeyStore.getEntry(KEY_ALIAS, null);
    Cipher inputCipher = Cipher.getInstance(RSA_MODE, "AndroidOpenSSL");
    inputCipher.init(Cipher.ENCRYPT_MODE, privateKeyEntry.getCertificate().getPublicKey());

    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, inputCipher);
    cipherOutputStream.write(secretAesKey);
    cipherOutputStream.close();

    return outputStream.toByteArray();
  }

  /**
   * Decrypts the encrypted AES key using the RSA private key in the keystore.
   *
   * @param encryptedAesKey A byte array representing the encrypted AES key.
   * @return A byte array representing the decrypted AES key.
   */
  private byte[] rsaDecrypt(byte[] encryptedAesKey) throws Exception {
    // 1.2.1. Get the private RSA key from keystore.
    KeyStore.PrivateKeyEntry privateKeyEntry =
        (KeyStore.PrivateKeyEntry) mKeyStore.getEntry(KEY_ALIAS, null);
    // 1.2.2. Initialize the block cipher using the private key.
    Cipher cipher = Cipher.getInstance(RSA_MODE, "AndroidOpenSSL");
    cipher.init(Cipher.DECRYPT_MODE, privateKeyEntry.getPrivateKey());
    // 1.2.3. Decrypt the encrypted AES key using the block cipher.
    CipherInputStream cipherInputStream =
        new CipherInputStream(new ByteArrayInputStream(encryptedAesKey), cipher);
    ArrayList<Byte> values = new ArrayList<>();
    int nextByte;
    while ((nextByte = cipherInputStream.read()) != -1) {
      values.add((byte) nextByte);
    }

    byte[] bytes = new byte[values.size()];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = values.get(i);
    }
    return bytes;
  }

  private String getDecryptedText(String encryptedText) throws Exception {
    // 1. Initialize the block cipher using
    // 1.1. the secret key from the keystore and IV from preferences (for M and higher).
    // 1.2. the decrypted AES key and IV stored in the preferences (for below M).
    // 2. Decrypt data using the block cipher.

    // To get the decrypted AES key:
    // 1.2.1. Get the private RSA key from keystore.
    // 1.2.2. Initialize the block cipher using the private key.
    // 1.2.3. Decrypt the encrypted AES key using the block cipher.
    Cipher cipher;

    // 1. Initialize the block cipher
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
      KeyStore.SecretKeyEntry secretKeyEntry =
          (KeyStore.SecretKeyEntry) mKeyStore.getEntry(KEY_ALIAS, null);
      SecretKey secretKey = secretKeyEntry.getSecretKey();

      cipher = Cipher.getInstance(AES_MODE);
      // 1.1. using the secret key from the keystore and IV from preferences (for M and higher).
      cipher.init(Cipher.DECRYPT_MODE, secretKey,
          new GCMParameterSpec(128, getKeyFromSharedPreferences(KEY_IV)));
    } else {
      cipher = Cipher.getInstance(AES_MODE, BLOCK_CIPHER_PROVIDER);
      // 1.2. using the decrypted AES key and IV stored in the preferences (for below M).
      cipher.init(Cipher.DECRYPT_MODE, getSecretAesKey(),
          new IvParameterSpec(getKeyFromSharedPreferences(KEY_IV)));
    }

    // 2. Decrypt data using the block cipher.
    CipherInputStream cipherInputStream = new CipherInputStream(
        new ByteArrayInputStream(Base64.decode(encryptedText, Base64.DEFAULT)), cipher);
    ArrayList<Byte> values = new ArrayList<>();
    int nextByte;
    while ((nextByte = cipherInputStream.read()) != -1) {
      values.add((byte) nextByte);
    }

    byte[] bytes = new byte[values.size()];
    for (int i = 0; i < bytes.length; i++) {
      bytes[i] = values.get(i);
    }

    return new String(bytes, 0, bytes.length, "UTF-8");
  }
}
