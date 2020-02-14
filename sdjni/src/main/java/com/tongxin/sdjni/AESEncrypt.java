package com.tongxin.sdjni;

/**
 * Created by carl on 20-02-06.
 *
 * SKF encrypt/decrypt native lib.
 */

public class AESEncrypt {
    public static final String DEVICE_NAME = "DEVICE_NAME";
    public static final String DEVICE_HANDLE = "DEVICE_NAME";

    static {
        System.loadLibrary("JNIEncrypt");
    }

    /**
     * set package name
     * @param str
     * @return 1 : pass ， -1 or  -2 : error.
     */
    public static native long setPackageName(String str);
    public static native String GetFuncList(String dev);
    public static native long ImportCert(int handle);
    public static native long ExportCert(int handle);
    public static native String EnumDev();
    public static native int ConnectDev(String dev);
    public static native long DisconnectDev(int handle);
    // cipher management
    public static native long GenRandom(int handle);
    public static native long GenECCKeyPair(int handle);
    public static native long ImportECCKey(int handle);
    public static native long ECCSignData(int handle);
    public static native long ECCVerify(int handle);
    public static native long GenDataWithECC(int handle);
    public static native long GenKeyWithECC(int handle);
    public static native long GenDataAndKeyWithECC(int handle);
    public static native long ExportPublicKey(int handle);
    public static native long ImportSessionKey(int handle);
    // cipher supplement service
    public static native long SetSymKey(int handle);
    public static native long CloseHandle(int handle);
    public static native String GetDevInfo(int handle);
    public static native long GetZA(int handle);
    public static native long EncryptInit(int handle);
    public static native long Encrypt(int handle);
    public static native long EncryptUpdate(int handle);
    public static native long EncryptFinal(int handle);
    public static native long DecryptInit(int handle);
    public static native long Decrypt(int handle);
    public static native long DecryptUpdate(int handle);
    public static native long DecryptFinal(int handle);
    public static native long DigestInit(int handle);
    public static native long Digest(int handle);
    public static native long DigestUpdate(int handle);
    public static native long DigestFinal(int handle);
    public static native long MacInit(int handle);
    public static native long MacUpdate(int handle);
    public static native long MacFinal(int handle);
    public static native long GenerateKey(int handle);
    public static native long ECCExportSessionKey(int handle);
    public static native long ECCPrvKeyDecrypt(int handle);
    public static native long ImportKeyPair(int handle);
    public static native long Cipher(int handle);

    public static native long BeginTransaction(int handle);
    public static native long EndTransaction(int handle);
    public static native String GetFirmVer(int handle);
    public static native String GetFlashID(int handle);
    public static native String ResetCard(int handle);
    public static native long ResetController(int handle, long control);
    public static native byte[] TransmitSd(int handle, byte[] command, long len, long mode);
    public static native byte[] TransmitEx(int handle, byte[] command, long mode);
    public static native String GetSDKVer();
    public static native long GetSCIOType(int handle);

}
