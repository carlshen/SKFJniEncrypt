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
import java.util.ArrayList;

/**
 * Created by carl on 20-02-06.
 *
 * 用于公司的项目验证。
 */
public class MainActivity extends AppCompatActivity {

    public static final String TAG = "MainActivity";
    private File[] appsDir;
    private String extPath;
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
    private Button mGenerateDataWithECC = null;
    private Button mGenerateKeyWithECC = null;
    private Button mGenerateDataAndKeyWithECC = null;
    private Button mExportPublicKey = null;
    private Button mImportSessionKey = null;
    private Button mCloseHandle = null;
    private Button mGetDevInfo = null;
    private Button mGetZA = null;
    private Button mNextPage = null;
    private String mECCData = null;
    private String ECCKeyPair = null;
    private String deviceName = "dev";
    private int deviceHandle = -1;
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
                deviceName = AESEncrypt.EnumDev();
                tvResult.setText("EnumDev: " + deviceName);
            }
        });
        mConnectDev = (Button) findViewById(R.id.btn_connect);
        mConnectDev.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                deviceHandle = AESEncrypt.ConnectDev(deviceName);
                tvResult.setText("ConnectDev: " + deviceHandle);
            }
        });
        mDisconnectDev = (Button) findViewById(R.id.btn_disconnect);
        mDisconnectDev.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = AESEncrypt.DisconnectDev(deviceHandle);
                tvResult.setText("DisconnectDev: " + result);
            }
        });

        mImportCert = (Button) findViewById(R.id.btn_importcert);
        mImportCert.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                StringBuilder encbuilder = new StringBuilder(1024);
                for (int i = 0; i < 32; i++) {
                    encbuilder.append("00112233445566778899001122334455");
                }
                String encode = encbuilder.toString();
                tvLog.setText("ImportCert string: " + encode);
                long result = AESEncrypt.ImportCert(deviceHandle, encode.getBytes());
                tvResult.setText("ImportCert result: " + result);
            }
        });
        mExportCert = (Button) findViewById(R.id.btn_exportcert);
        mExportCert.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                byte[] result = AESEncrypt.ExportCert(deviceHandle);
                if (result != null) {
                    tvLog.setText("ExportCert result: " + EncryptUtil.ByteArrayToHexString(result));
                    tvResult.setText("ExportCert result length: " + result.length);
                } else {
                    tvResult.setText("ExportCert result failed. ");
                }
            }
        });
        mSetAppPath = (Button) findViewById(R.id.btn_setpath);
        mSetAppPath.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                callTongfang();
                tvResult.setText("setPackageName: ok.");
            }
        });
        mGetFuncList = (Button) findViewById(R.id.btn_getfunc);
        mGetFuncList.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String result = AESEncrypt.GetFuncList();
                tvLog.setText("GetFuncList: " + result);
            }
        });
        mGenRandom = (Button) findViewById(R.id.btn_genrandom);
        mGenRandom.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String result = AESEncrypt.GenRandom(deviceHandle);
                tvResult.setText("GenRandom: " + result);
            }
        });
        mGenECCKeyPair = (Button) findViewById(R.id.btn_genecckey);
        mGenECCKeyPair.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = AESEncrypt.GenECCKeyPair(deviceHandle);
                tvResult.setText("GenECCKeyPair: " + result);
            }
        });
        mImportECCKeyPair = (Button) findViewById(R.id.btn_importecckey);
        mImportECCKeyPair.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = AESEncrypt.ImportECCKey(deviceHandle);
                tvResult.setText("ImportECCKey: " + result);
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
                long result = AESEncrypt.ECCSignData(deviceHandle);
                tvResult.setText("ECCSignData: " + result);
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
                long result = AESEncrypt.ECCVerify(deviceHandle);
                tvResult.setText("ECCVerify: " + result);
            }
        });
        mGenerateDataWithECC = (Button) findViewById(R.id.btn_gendatawithecc);
        mGenerateDataWithECC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (TextUtils.isEmpty(DecrpytData)) {
                    tvResult.setText("SKF_Decrypt: There is no decrypt data");
                    return;
                }
                long result = AESEncrypt.GenDataWithECC(deviceHandle);
                tvResult.setText("GenDataWithECC: " + result);
            }
        });
        mGenerateKeyWithECC = (Button) findViewById(R.id.btn_genkeywithecc);
        mGenerateKeyWithECC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = AESEncrypt.GenKeyWithECC(deviceHandle);
                tvResult.setText("GenKeyWithECC: " + result);
            }
        });
        mGenerateDataAndKeyWithECC = (Button) findViewById(R.id.btn_gendatakeywithecc);
        mGenerateDataAndKeyWithECC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = AESEncrypt.GenDataAndKeyWithECC(deviceHandle);
                tvResult.setText("GenDataAndKeyWithECC: " + result);
            }
        });
        mExportPublicKey = (Button) findViewById(R.id.btn_exportpublickey);
        mExportPublicKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = AESEncrypt.ExportPublicKey(deviceHandle);
                tvResult.setText("ExportPublicKey: " + result);
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
                long result = AESEncrypt.ImportSessionKey(deviceHandle);
                tvResult.setText("ImportSessionKey: " + result);
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
        mNextPage = (Button) findViewById(R.id.btn_nextpage);
        mNextPage.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent intent = new Intent(MainActivity.this, SyncActivity.class);
                intent.putExtra(AESEncrypt.DEVICE_NAME, deviceName);
                intent.putExtra(AESEncrypt.DEVICE_HANDLE, deviceHandle);
                startActivity(intent);
            }
        });

        // need init
        callTongfang();
    }

    private void callTongfang() {
        appsDir = getExternalFilesDirs("/");
        String appPath = "Android/data/" + getPackageName();
        long result = AESEncrypt.setPackageName(appPath);
        Log.i(TAG, "appPath: " + appPath);
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
        ArrayList<StorageBean> gg = StorageUtils.getStorageData(getApplicationContext());
        StringBuilder cardBuilder = new StringBuilder(256);
        for (StorageBean bean: gg) {
            Log.d("MainActivity", "bean.getPath(): " + bean.getPath());
            Log.d("MainActivity", "bean.getTotalSize(): " + bean.getTotalSize());
            cardBuilder.append(bean.getPath() + "\n");
            StorageUtils.EXTERNAL_SDCARD = bean.getPath();
            if (!bean.getPath().toLowerCase().contains("emulated")) {
//                extPath = bean.getPath();
//                StorageUtils.EXTERNAL_SDCARD = bean.getPath();
                break;
            }
        }
        Log.i(TAG, "cardBuilder: " + cardBuilder.toString());
        extPath = StorageUtils.EXTERNAL_SDCARD + "/Android/data/" + getPackageName();
//        extPath = "/sdcard/Android/data/" + getPackageName();
        tvLog.setText("ExternalFilesDir: " + extPath);
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
