package com.tongxin.sdjniencrypt;

import android.Manifest;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import java.io.File;

/**
 * Created by carl on 2019/12/31.
 */
public class SyncActivity extends AppCompatActivity {

    public static final String TAG = "SyncActivity";
    private boolean mLogShown = false;
    private Button mButtonEnum = null;
    private Button mButtonConnect = null;
    private Button mButtonInfo = null;
    private Button mButtonDisconnect = null;
    // container management
    private Button mImportCert = null;
    private Button mExportCert = null;
    // cipher management
    private Button mGenRandom = null;
    private Button mSyncDemo = null;
    private Button mSetSymKey = null;
    private Button mGetSymKey = null;
    private Button mCheckSymKey = null;
    private Button mEncrInit = null;
    private Button mEncrypt = null;
    private Button mDecrInit = null;
    private Button mDecrypt = null;
    private Button mEncryptFile = null;
    private Button mDecryptFile = null;
    private Button mDigestInit = null;
    private Button mDigest = null;
    private Button mECCKey = null;
    private Button mECCSign = null;
    private Button mECCVerify = null;
    private Button mSetPin = null;
    private Button mGetPin = null;
    private String mECCData = null;
    private String ECCKeyPair = null;
    private TextView tvResult = null;
    private String deviceName = null;
    private String deviceData = null;
    private String KeyData = null;
    private String EncrpytData = null;
    private String DecrpytData = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_sync);

        tvResult = (TextView) findViewById(R.id.tv_result);
        mButtonEnum = (Button) findViewById(R.id.btn_device);
        mButtonEnum.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                SkfInterface.getSkfInstance().SKF_EnumDev(getApplicationContext());
            }
        });
        mButtonConnect = (Button) findViewById(R.id.btn_connect);
        mButtonConnect.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                boolean result = SkfInterface.getSkfInstance().SKF_ConnectDev(deviceName);
//                tvResult.setText("ConnectDev: " + result);
            }
        });
        mButtonInfo = (Button) findViewById(R.id.btn_info);
        mButtonInfo.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                boolean result = SkfInterface.getSkfInstance().SKF_GetDevInfo(deviceName);
//                tvResult.setText("DevInfo: " + result);
            }
        });
        mButtonDisconnect = (Button) findViewById(R.id.btn_disconnect);
        mButtonDisconnect.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                boolean result = SkfInterface.getSkfInstance().SKF_DisconnectDev(deviceName);
//                tvResult.setText("DisconnectDev: " + result);
            }
        });

        // ======== next 2nd interfaces
        mImportCert = (Button) findViewById(R.id.btn_createapp);
        mImportCert.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                boolean result = SkfInterface.getSkfInstance().SKF_CreateApplication(deviceName);
//                tvResult.setText("DisconnectDev: " + result);
            }
        });
        mExportCert = (Button) findViewById(R.id.btn_openapp);
        mExportCert.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                boolean result = SkfInterface.getSkfInstance().SKF_OpenApplication(deviceName);
//                tvResult.setText("DisconnectDev: " + result);
            }
        });
        mGenRandom = (Button) findViewById(R.id.btn_createcon);
        mGenRandom.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                boolean result = SkfInterface.getSkfInstance().SKF_CreateContainer(deviceName);
//                tvResult.setText("DisconnectDev: " + result);
            }
        });
        mSetSymKey = (Button) findViewById(R.id.btn_setsymkey);
        mSetSymKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String symKey = "";
                byte[] key = null;
                try {
                    key = EncryptUtil.generateKey();
                    symKey = EncryptUtil.ByteArrayToHexString(key);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                Log.i(TAG, "====== mSetSymKey = " + symKey);
//                boolean result = SkfInterface.getSkfInstance().SKF_SetSymmKey(deviceName, key, 1025);
//                tvResult.setText("DisconnectDev: " + result);
            }
        });
        mCheckSymKey = (Button) findViewById(R.id.btn_checkkey);
        mCheckSymKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                boolean result = SkfInterface.getSkfInstance().SKF_CheckSymmKey(deviceName);
//                tvResult.setText("DisconnectDev: " + result);
            }
        });
        mGetSymKey = (Button) findViewById(R.id.btn_getkey);
        mGetSymKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                boolean result = SkfInterface.getSkfInstance().SKF_GetSymmKey(deviceName, 1025);
//                tvResult.setText("DisconnectDev: " + result);
            }
        });
        mEncrInit = (Button) findViewById(R.id.btn_encrinit);
        mEncrInit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                boolean result = SkfInterface.getSkfInstance().SKF_EncryptInit(KeyData);
//                tvResult.setText("DisconnectDev: " + result);
            }
        });
        mEncrypt = (Button) findViewById(R.id.btn_encrpyt);
        mEncrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                StringBuilder encbuilder = new StringBuilder(1024);
                for (int i = 0; i < 28; i++) {
                    encbuilder.append("112233445566778899001122334455667788aabb");
                }
                EncrpytData = encbuilder.toString();
//                boolean result = SkfInterface.getSkfInstance().SKF_Encrypt(KeyData, EncrpytData.getBytes());
//                tvResult.setText("DisconnectDev: " + result);
            }
        });
        mDecrInit = (Button) findViewById(R.id.btn_decrinit);
        mDecrInit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                boolean result = SkfInterface.getSkfInstance().SKF_DecryptInit(KeyData);
//                tvResult.setText("DisconnectDev: " + result);
            }
        });
        mDecrypt = (Button) findViewById(R.id.btn_decrypt);
        mDecrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (TextUtils.isEmpty(DecrpytData)) {
                    tvResult.setText("SKF_Decrypt: There is no decrypt data");
                    return;
                }
//                boolean result = SkfInterface.getSkfInstance().SKF_Decrypt(KeyData, EncryptUtil.HexStringToByteArray(DecrpytData));
            }
        });
        mEncryptFile = (Button) findViewById(R.id.btn_encrfile);
        mEncryptFile.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        File inFile = new File(EncryptUtil.getExternalStoragePath() + "/entest.txt");
                        File ouFile = new File(EncryptUtil.getExternalAppFilesPath(getApplicationContext()) + "/enresult.txt");
                        try {
//                            boolean result = SkfInterface.getSkfInstance().SKF_EncryptFile(KeyData, inFile, ouFile);
//                            tvResult.setText("EncryptFile: " + result);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }).start();
            }
        });
        mDecryptFile = (Button) findViewById(R.id.btn_decrfile);
        mDecryptFile.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
//                        File inFile = new File(EncryptUtil.getExternalStoragePath() + "/detest.txt");
                        File inFile = new File(EncryptUtil.getExternalAppFilesPath(getApplicationContext()) + "/enresult.txt");
                        File ouFile = new File(EncryptUtil.getExternalAppFilesPath(getApplicationContext()) + "/deresult.txt");
                        try {
//                            boolean result = SkfInterface.getSkfInstance().SKF_DecryptFile(KeyData, inFile, ouFile);
//                            tvResult.setText("DecryptFile: " + result);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }).start();
            }
        });
        mDigestInit = (Button) findViewById(R.id.btn_digestinit);
        mDigestInit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                boolean result = SkfInterface.getSkfInstance().SKF_DigestInit(deviceName);
//                tvResult.setText("DisconnectDev: " + result);
            }
        });
        mDigest = (Button) findViewById(R.id.btn_digest);
        mDigest.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                StringBuilder encbuilder = new StringBuilder(1024);
                for (int i = 0; i < 28; i++) {
                    encbuilder.append("1122334455667788990011223344556677889900");
                }
                EncrpytData = encbuilder.toString();
//                boolean result = SkfInterface.getSkfInstance().SKF_Digest(EncryptUtil.HexStringToByteArray(EncrpytData));
//                tvResult.setText("DisconnectDev: " + result);
            }
        });
        mECCKey = (Button) findViewById(R.id.btn_ecckey);
        mECCKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                boolean result = SkfInterface.getSkfInstance().SKF_GenECCKeyPair(deviceName);
//                tvResult.setText("DisconnectDev: " + result);
            }
        });
        mECCSign = (Button) findViewById(R.id.btn_eccsign);
        mECCSign.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                StringBuilder encbuilder = new StringBuilder(1024);
                for (int i = 0; i < 28; i++) {
                    encbuilder.append("1122334455667788990011223344556677889900");
                }
                EncrpytData = encbuilder.toString();
//                boolean result = SkfInterface.getSkfInstance().SKF_ECCSignData(ECCKeyPair, EncryptUtil.HexStringToByteArray(EncrpytData));
//                tvResult.setText("DisconnectDev: " + result);
            }
        });
        mECCVerify = (Button) findViewById(R.id.btn_eccverify);
        mECCVerify.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                StringBuilder encbuilder = new StringBuilder(1024);
                for (int i = 0; i < 28; i++) {
                    encbuilder.append("1122334455667788990011223344556677889900");
                }
                EncrpytData = encbuilder.toString();
//                boolean result = SkfInterface.getSkfInstance().SKF_ECCVerify(ECCKeyPair, mECCData, EncryptUtil.HexStringToByteArray(EncrpytData));
//                tvResult.setText("DisconnectDev: " + result);
            }
        });
        mSetPin = (Button) findViewById(R.id.btn_setpin);
        mSetPin.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                boolean result = SkfInterface.getSkfInstance().SKF_SetPIN(deviceName, EncryptUtil.HexStringToByteArray("112233445566778899001122334455667788990011223344556677889900112233445566"));
//                tvResult.setText("DisconnectDev: " + result);
            }
        });
        mGetPin = (Button) findViewById(R.id.btn_getpin);
        mGetPin.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                boolean result = SkfInterface.getSkfInstance().SKF_GetPIN(deviceName);
//                tvResult.setText("DisconnectDev: " + result);
            }
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (Build.VERSION.SDK_INT>=Build.VERSION_CODES.M){
            if (ContextCompat.checkSelfPermission(SyncActivity.this, Manifest.permission.WRITE_EXTERNAL_STORAGE)!= PackageManager.PERMISSION_GRANTED){
                ActivityCompat.requestPermissions(SyncActivity.this,new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE},1);
            }
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        switch (requestCode){
            case 1:
                if (grantResults.length>0&&grantResults[0]!=PackageManager.PERMISSION_GRANTED){
                    finish();
                }
                break;
        }
    }

}
