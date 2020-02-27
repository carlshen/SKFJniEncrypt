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
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.tongxin.sdjni.AESEncrypt;

/**
 * Created by carl on 20-02-06.
 *
 * 用于公司的项目验证。
 */
public class SyncActivity extends AppCompatActivity {

    public static final String TAG = "SyncActivity";
    private TextView tvResult = null;
    private TextView tvLog = null;
    // next 2nd page
    private Button mSetSymKey = null;
    private Button mCloseHandle = null;
    private Button mGetDevInfo = null;
    private Button mGetZA = null;
    // encrypt / decrypt
    private Button mEncryptInit = null;
    private Button mEncrypt = null;
    private Button mEncryptUpdate = null;
    private Button mEncryptFinal = null;
    private Button mDecryptInit = null;
    private Button mDecrypt = null;
    private Button mDecryptUpdate = null;
    private Button mDecryptFinal = null;
    private Button mDigestInit = null;
    private Button mDigest = null;
    private Button mDigestUpdate = null;
    private Button mDigestFinal = null;
    private Button mMacInit = null;
    private Button mMacUpdate = null;
    private Button mMacFinal = null;
    private Button mGenerateKey = null;
    private Button mECCExportSessionKey = null;
    private Button mECCPrvKeyDecrypt = null;
    private Button mImportKeyPair = null;
    private Button mCipher = null;

    private String mECCData = null;
    private String ECCKeyPair = null;
    private int deviceHandle = -1;
    private String deviceName = null;
    private String deviceData = null;
    private String KeyData = null;
    private String EncrpytData = null;
    private String DecrpytData = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_sync);
        Intent intent = getIntent();
        if (intent != null) {
            deviceName = intent.getStringExtra(AESEncrypt.DEVICE_NAME);
            deviceHandle = intent.getIntExtra(AESEncrypt.DEVICE_HANDLE, -1);
        }

        tvResult = (TextView) findViewById(R.id.tv_result);
        tvLog = (TextView) findViewById(R.id.tv_log);

        mSetSymKey = (Button) findViewById(R.id.btn_setsymkey);
        mSetSymKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = AESEncrypt.SetSymKey(deviceHandle);
                tvResult.setText("SetSymKey: " + result);
            }
        });
        mCloseHandle = (Button) findViewById(R.id.btn_closehandle);
        mCloseHandle.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = AESEncrypt.CloseHandle(deviceHandle);
                tvResult.setText("CloseHandle: " + result);
            }
        });
        mGetDevInfo = (Button) findViewById(R.id.btn_getdevinfo);
        mGetDevInfo.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String result = AESEncrypt.GetDevInfo(deviceHandle);
                tvResult.setText("GetDevInfo: " + result);
            }
        });
        mGetZA = (Button) findViewById(R.id.btn_getza);
        mGetZA.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                StringBuilder encbuilder = new StringBuilder(64);
                for (int i = 0; i < 2; i++) {
                    encbuilder.append("00112233445566778899001122334455");
                }
                String encode = encbuilder.toString();
                tvLog.setText("mGetZA string: " + encode);
                long result = AESEncrypt.GetZA(deviceHandle, encode.getBytes());
                tvResult.setText("GetZA: " + result);
            }
        });
        mEncryptInit = (Button) findViewById(R.id.btn_encryptInit);
        mEncryptInit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = AESEncrypt.EncryptInit(deviceHandle);
                tvResult.setText("EncryptInit: " + result);
            }
        });
        mEncrypt = (Button) findViewById(R.id.btn_encrypt);
        mEncrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = AESEncrypt.Encrypt(deviceHandle);
                tvResult.setText("Encrypt: " + result);
            }
        });
        mEncryptUpdate = (Button) findViewById(R.id.btn_encryptupdate);
        mEncryptUpdate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = AESEncrypt.EncryptUpdate(deviceHandle);
                tvResult.setText("EncryptUpdate: " + result);
            }
        });
        mEncryptFinal = (Button) findViewById(R.id.btn_encryptfinal);
        mEncryptFinal.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = AESEncrypt.EncryptFinal(deviceHandle);
                tvResult.setText("EncryptFinal: " + result);
            }
        });
        mDecryptInit = (Button) findViewById(R.id.btn_decryptInit);
        mDecryptInit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = AESEncrypt.DecryptInit(deviceHandle);
                tvResult.setText("DecryptInit: " + result);
            }
        });
        mDecrypt = (Button) findViewById(R.id.btn_decrypt);
        mDecrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = AESEncrypt.Decrypt(deviceHandle);
                tvResult.setText("Decrypt: " + result);
            }
        });
        mDecryptUpdate = (Button) findViewById(R.id.btn_decryptupdate);
        mDecryptUpdate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = AESEncrypt.DecryptUpdate(deviceHandle);
                tvResult.setText("DecryptUpdate: " + result);
            }
        });
        mDecryptFinal = (Button) findViewById(R.id.btn_decryptfinal);
        mDecryptFinal.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = AESEncrypt.DecryptFinal(deviceHandle);
                tvResult.setText("DecryptFinal: " + result);
            }
        });
        mDigestInit = (Button) findViewById(R.id.btn_digestInit);
        mDigestInit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                StringBuilder encbuilder = new StringBuilder(1024);
                for (int i = 0; i < 28; i++) {
                    encbuilder.append("112233445566778899001122334455667788aabb");
                }
                EncrpytData = encbuilder.toString();
                long result = AESEncrypt.DigestInit(deviceHandle);
                tvResult.setText("DigestInit: " + result);
            }
        });
        mDigest = (Button) findViewById(R.id.btn_digest);
        mDigest.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = AESEncrypt.Digest(deviceHandle);
                tvResult.setText("Digest: " + result);
            }
        });
        mDigestUpdate = (Button) findViewById(R.id.btn_digestupdate);
        mDigestUpdate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (TextUtils.isEmpty(DecrpytData)) {
                    tvResult.setText("SKF_Decrypt: There is no decrypt data");
                    return;
                }
                long result = AESEncrypt.DigestUpdate(deviceHandle);
                tvResult.setText("DigestUpdate: " + result);
            }
        });
        mDigestFinal = (Button) findViewById(R.id.btn_digestfinal);
        mDigestFinal.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = AESEncrypt.DigestFinal(deviceHandle);
                tvResult.setText("DigestFinal: " + result);
            }
        });
        mMacInit = (Button) findViewById(R.id.btn_MacInit);
        mMacInit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = AESEncrypt.MacInit(deviceHandle);
                tvResult.setText("MacInit: " + result);
            }
        });
        mMacUpdate = (Button) findViewById(R.id.btn_MacUpdate);
        mMacUpdate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = AESEncrypt.MacUpdate(deviceHandle);
                tvResult.setText("MacUpdate: " + result);
            }
        });
        mMacFinal = (Button) findViewById(R.id.btn_MacFinal);
        mMacFinal.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                StringBuilder encbuilder = new StringBuilder(1024);
                for (int i = 0; i < 28; i++) {
                    encbuilder.append("1122334455667788990011223344556677889900");
                }
                EncrpytData = encbuilder.toString();
                long result = AESEncrypt.MacFinal(deviceHandle);
                tvResult.setText("MacFinal: " + result);
            }
        });
        mGenerateKey = (Button) findViewById(R.id.btn_generatekey);
        mGenerateKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = AESEncrypt.GenerateKey(deviceHandle);
                tvResult.setText("GenerateKey: " + result);
            }
        });
        mECCExportSessionKey = (Button) findViewById(R.id.btn_eccexportkey);
        mECCExportSessionKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                StringBuilder encbuilder = new StringBuilder(1024);
                for (int i = 0; i < 28; i++) {
                    encbuilder.append("1122334455667788990011223344556677889900");
                }
                EncrpytData = encbuilder.toString();
                long result = AESEncrypt.ECCExportSessionKey(deviceHandle);
                tvResult.setText("ECCExportSessionKey: " + result);
            }
        });
        mECCPrvKeyDecrypt = (Button) findViewById(R.id.btn_ecckeydecrypt);
        mECCPrvKeyDecrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                StringBuilder encbuilder = new StringBuilder(1024);
                for (int i = 0; i < 28; i++) {
                    encbuilder.append("1122334455667788990011223344556677889900");
                }
                EncrpytData = encbuilder.toString();
                long result = AESEncrypt.ECCPrvKeyDecrypt(deviceHandle);
                tvResult.setText("ECCPrvKeyDecrypt: " + result);
            }
        });
        mImportKeyPair = (Button) findViewById(R.id.btn_importkey);
        mImportKeyPair.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = AESEncrypt.ImportKeyPair(deviceHandle);
                tvResult.setText("ImportKeyPair: " + result);
            }
        });
        mCipher = (Button) findViewById(R.id.btn_cipher);
        mCipher.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = AESEncrypt.Cipher(deviceHandle);
                tvResult.setText("Cipher: " + result);
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
