package com.tongxin.sdjniencrypt;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.tongxin.sdjni.AESEncrypt;

import java.io.File;

/**
 * Created by carl on 20-02-06.
 *
 * 用于公司的项目验证。
 */
public class MainActivity extends AppCompatActivity {

    public static final String TAG = "MainActivity";
    private File[] appsDir;
    private boolean mLogShown = false;
    private TextView tvResult = null;
    private TextView tvLog = null;
    // device management
    private Button mEnumDev = null;
    private Button mConnectDev = null;
    private Button mDisconnectDev = null;
    // container management
    private Button mImportCert = null;
    private Button mExportCert = null;
    // device
    private Button mSetAppPath = null;
    private Button mGetFuncList = null;
    // cipher management
    private Button mGenRandom = null;
    private Button mGenECCKeyPair = null;
    private Button mImportECCKeyPair = null;
    private Button mECCSignData = null;
    private Button mECCVerify = null;
    private Button mGenerateAgreementDataWithECC = null;
    private Button mGenerateKeyWithECC = null;
    private Button mGenerateAgreementDataAndKeyWithECC = null;
    private Button mExportPublicKey = null;
    private Button mImportSessionKey = null;
    private Button mNextPage = null;
    // next 2nd page
//    private Button mSetSymKey = null;
//    private Button mEncryptInit = null;
//    private Button mEncrypt = null;
//    private Button mEncryptUpdate = null;
//    private Button mEncryptFinal = null;
//    private Button mDecryptInit = null;
//    private Button mDecrypt = null;
//    private Button mDecryptUpdate = null;
//    private Button mDecryptFinal = null;
//    private Button mDigestInit = null;
//    private Button mDigest = null;
//    private Button mDigestUpdate = null;
//    private Button mDigestFinal = null;
//    private Button mMacInit = null;
//    private Button mMacUpdate = null;
//    private Button mMacFinal = null;
//    private Button mCloseHandle = null;
//    private Button mGetDevInfo = null;
//    private Button mGenerateKey = null;
//    private Button mECCExportSessionKeyByHandle = null;
//    private Button mECCPrvKeyDecrypt = null;
//    private Button mImportKeyPair = null;
//    private Button mCipher = null;
    private String mECCData = null;
    private String ECCKeyPair = null;
    private String deviceName = null;
    private String deviceData = null;
    private String KeyData = null;
    private String EncrpytData = null;
    private String DecrpytData = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        tvResult = (TextView) findViewById(R.id.tv_result);
        tvLog = (TextView) findViewById(R.id.tv_log);
        mEnumDev = (Button) findViewById(R.id.btn_device);
        mEnumDev.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                SkfInterface.getSkfInstance().SKF_EnumDev(getApplicationContext());
            }
        });
        mConnectDev = (Button) findViewById(R.id.btn_connect);
        mConnectDev.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                boolean result = SkfInterface.getSkfInstance().SKF_ConnectDev(deviceName);
//                tvResult.setText("ConnectDev: " + result);
            }
        });
        mDisconnectDev = (Button) findViewById(R.id.btn_disconnect);
        mDisconnectDev.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                boolean result = SkfInterface.getSkfInstance().SKF_DisconnectDev(deviceName);
//                tvResult.setText("DisconnectDev: " + result);
            }
        });

        mImportCert = (Button) findViewById(R.id.btn_importcert);
        mImportCert.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                boolean result = SkfInterface.getSkfInstance().SKF_CreateApplication(deviceName);
//                tvResult.setText("DisconnectDev: " + result);
            }
        });
        mExportCert = (Button) findViewById(R.id.btn_exportcert);
        mExportCert.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                boolean result = SkfInterface.getSkfInstance().SKF_OpenApplication(deviceName);
//                tvResult.setText("DisconnectDev: " + result);
            }
        });
        mSetAppPath = (Button) findViewById(R.id.btn_setpath);
        mSetAppPath.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                boolean result = SkfInterface.getSkfInstance().SKF_CheckSymmKey(deviceName);
//                tvResult.setText("DisconnectDev: " + result);
            }
        });
        mGetFuncList = (Button) findViewById(R.id.btn_getfunc);
        mGetFuncList.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                boolean result = SkfInterface.getSkfInstance().SKF_GetSymmKey(deviceName, 1025);
//                tvResult.setText("DisconnectDev: " + result);
            }
        });
        mGenRandom = (Button) findViewById(R.id.btn_genrandom);
        mGenRandom.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
            }
        });
        mGenECCKeyPair = (Button) findViewById(R.id.btn_genecckey);
        mGenECCKeyPair.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                Intent intent = new Intent(MainActivity.this, SyncActivity.class);
//                startActivity(intent);
            }
        });
        mImportECCKeyPair = (Button) findViewById(R.id.btn_importecckey);
        mImportECCKeyPair.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                boolean result = SkfInterface.getSkfInstance().SKF_EncryptInit(KeyData);
//                tvResult.setText("DisconnectDev: " + result);
            }
        });
        mECCSignData = (Button) findViewById(R.id.btn_eccsigndata);
        mECCSignData.setOnClickListener(new View.OnClickListener() {
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
        mECCVerify = (Button) findViewById(R.id.btn_eccverify);
        mECCVerify.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                boolean result = SkfInterface.getSkfInstance().SKF_DecryptInit(KeyData);
//                tvResult.setText("DisconnectDev: " + result);
            }
        });
        mGenerateAgreementDataWithECC = (Button) findViewById(R.id.btn_gendatawithecc);
        mGenerateAgreementDataWithECC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (TextUtils.isEmpty(DecrpytData)) {
                    tvResult.setText("SKF_Decrypt: There is no decrypt data");
                    return;
                }
//                boolean result = SkfInterface.getSkfInstance().SKF_Decrypt(KeyData, EncryptUtil.HexStringToByteArray(DecrpytData));
            }
        });
        mGenerateKeyWithECC = (Button) findViewById(R.id.btn_genkeywithecc);
        mGenerateKeyWithECC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
            }
        });
        mGenerateAgreementDataAndKeyWithECC = (Button) findViewById(R.id.btn_gendatakeywithecc);
        mGenerateAgreementDataAndKeyWithECC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
            }
        });
        mExportPublicKey = (Button) findViewById(R.id.btn_exportpublickey);
        mExportPublicKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                boolean result = SkfInterface.getSkfInstance().SKF_DigestInit(deviceName);
//                tvResult.setText("DisconnectDev: " + result);
            }
        });
        mImportSessionKey = (Button) findViewById(R.id.btn_exportsessionkey);
        mImportSessionKey.setOnClickListener(new View.OnClickListener() {
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
        mNextPage = (Button) findViewById(R.id.btn_nextpage);
        mNextPage.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent intent = new Intent(MainActivity.this, SyncActivity.class);
                startActivity(intent);
            }
        });

        // need init
        callTongfang();
    }

    private void callTongfang() {
        appsDir = getExternalFilesDirs("/");
        long result = AESEncrypt.setPackageName(getPackageName());
        Log.i(TAG, "getPackageName(): " + getPackageName());
        Log.i(TAG, "setPackageName result: " + result);
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (Build.VERSION.SDK_INT>=Build.VERSION_CODES.M){
            if (ContextCompat.checkSelfPermission(MainActivity.this, Manifest.permission.WRITE_EXTERNAL_STORAGE)!= PackageManager.PERMISSION_GRANTED){
                ActivityCompat.requestPermissions(MainActivity.this,new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE},1);
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
