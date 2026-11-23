use std::collections::{BTreeSet, HashMap, HashSet};

pub fn default_sinks() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        (
            "webview_loadurl",
            vec![
                "android.webkit.WebView.loadUrl",
                "android.webkit.WebView.postUrl",
            ],
        ),
        (
            "html_injection_loaddata",
            vec![
                "android.webkit.WebView.loadDataWithBaseURL",
                "android.webkit.WebView.loadData",
            ],
        ),
        (
            "js_bridge_call",
            vec!["android.webkit.WebView.evaluateJavascript"],
        ),
        (
            "webview_settings",
            vec![
                "android.webkit.WebSettings.setJavaScriptEnabled",
                "android.webkit.WebView.addJavascriptInterface",
                "android.webkit.WebSettings.setAllowFileAccess",
                "android.webkit.WebSettings.setAllowFileAccessFromFileURLs",
                "android.webkit.WebSettings.setAllowUniversalAccessFromFileURLs",
                "android.webkit.WebSettings.setJavaScriptCanOpenWindowsAutomatically",
            ],
        ),
        (
            "token_exfil_via_webview",
            vec![
                "android.webkit.CookieManager.setCookie",
                "android.webkit.CookieManager.getCookie",
            ],
        ),
        (
            "file_chooser_abuse",
            vec!["android.webkit.ValueCallback.onReceiveValue"],
        ),
        (
            "intent_launch",
            vec![
                "android.content.Context.startActivity",
                "android.content.Context.startActivities",
                "android.app.Activity.startActivityForResult",
                "android.app.Fragment.startActivity",
                "android.app.Fragment.startActivityForResult",
                "androidx.fragment.app.Fragment.startActivity",
                "androidx.fragment.app.Fragment.startActivityForResult",
                "android.content.Context.startService",
                "android.content.Context.startForegroundService",
                "android.content.Context.bindService",
                "android.content.Context.sendBroadcast",
                "android.content.Context.sendOrderedBroadcast",
                "android.app.PendingIntent.getActivity",
                "android.app.PendingIntent.getBroadcast",
                "android.app.PendingIntent.getService",
            ],
        ),
        (
            "intent_parse",
            vec![
                "android.content.Intent.parseUri",
                "android.content.Intent.getIntent",
                "android.content.Intent.getIntentOld",
            ],
        ),
        (
            "parcelable_extra_injection",
            vec![
                "android.content.Intent.getParcelableExtra",
                "android.content.Intent.getSerializableExtra",
                "android.os.Bundle.getParcelable",
                "android.os.Bundle.getSerializable",
            ],
        ),
        (
            "file_read",
            vec![
                "java.io.FileInputStream.<init>",
                "android.content.Context.openFileInput",
                "android.content.ContentResolver.openInputStream",
            ],
        ),
        (
            "file_write",
            vec![
                "java.io.FileOutputStream.<init>",
                "java.io.FileOutputStream.write",
                "android.content.Context.openFileOutput",
                "java.nio.file.Files.write",
                "android.content.ContentResolver.openOutputStream",
            ],
        ),
        (
            "content_provider_write",
            vec![
                "android.content.ContentResolver.openFileDescriptor",
                "android.content.ContentResolver.openAssetFileDescriptor",
            ],
        ),
        (
            "zip_extract",
            vec![
                "java.util.zip.ZipInputStream.getNextEntry",
                "java.util.zip.ZipFile.getInputStream",
                "java.util.zip.ZipEntry.getName",
            ],
        ),
        (
            "exec",
            vec![
                "java.lang.Runtime.exec",
                "java.lang.ProcessBuilder.start",
            ],
        ),
        (
            "native_load",
            vec![
                "java.lang.System.load",
                "java.lang.System.loadLibrary",
                "java.lang.Runtime.load",
                "java.lang.Runtime.loadLibrary",
            ],
        ),
        (
            "class_load",
            vec![
                "java.lang.Class.forName",
                "java.lang.ClassLoader.loadClass",
                "dalvik.system.DexClassLoader.<init>",
                "dalvik.system.PathClassLoader.<init>",
                "dalvik.system.InMemoryDexClassLoader.<init>",
                "dalvik.system.BaseDexClassLoader.<init>",
            ],
        ),
        (
            "content_share",
            vec![
                "android.content.ClipboardManager.setPrimaryClip",
                "android.text.ClipboardManager.setText",
            ],
        ),
        (
            "network_request",
            vec![
                "java.net.URL.openConnection",
                "java.net.URL.openStream",
                "java.net.URLConnection.connect",
            ],
        ),
        (
            "crypto_misuse",
            vec![
                "javax.crypto.Cipher.init",
                "javax.crypto.Cipher.getInstance",
            ],
        ),
        (
            "account_authenticator",
            vec![
                "android.accounts.AccountManager.getAuthToken",
                "android.accounts.AccountManager.addAccount",
                "android.accounts.AccountManager.getAccountsByType",
            ],
        ),
    ]
}

pub struct FrameworkKnowledge {
    /// Direct supertypes (superclass + interfaces) of standard Android & Java classes
    pub direct_parents: HashMap<String, Vec<String>>,
    /// Known methods declared on standard Android & Java classes
    pub declared_methods: HashMap<String, HashSet<String>>,
}

impl FrameworkKnowledge {
    pub fn new() -> Self {
        let mut direct_parents: HashMap<String, Vec<String>> = HashMap::new();
        let mut declared_methods: HashMap<String, HashSet<String>> = HashMap::new();

        let parents_table: &[(&str, &[&str])] = &[
            ("java.lang.Object", &[]),
            ("java.lang.Throwable", &["java.lang.Object", "java.io.Serializable"]),
            ("java.lang.Exception", &["java.lang.Throwable"]),
            ("java.lang.RuntimeException", &["java.lang.Exception"]),
            ("java.lang.Error", &["java.lang.Throwable"]),
            ("java.lang.Thread", &["java.lang.Object", "java.lang.Runnable"]),
            ("java.lang.Runnable", &["java.lang.Object"]),
            ("java.lang.CharSequence", &["java.lang.Object"]),
            ("java.lang.String", &["java.lang.Object", "java.io.Serializable", "java.lang.Comparable", "java.lang.CharSequence"]),
            ("java.lang.ClassLoader", &["java.lang.Object"]),
            ("dalvik.system.BaseDexClassLoader", &["java.lang.ClassLoader"]),
            ("dalvik.system.DexClassLoader", &["dalvik.system.BaseDexClassLoader"]),
            ("dalvik.system.PathClassLoader", &["dalvik.system.BaseDexClassLoader"]),
            ("dalvik.system.InMemoryDexClassLoader", &["dalvik.system.BaseDexClassLoader"]),
            ("java.io.Closeable", &["java.lang.AutoCloseable", "java.lang.Object"]),
            ("java.io.InputStream", &["java.lang.Object", "java.io.Closeable"]),
            ("java.io.OutputStream", &["java.lang.Object", "java.io.Closeable", "java.io.Flushable"]),
            ("java.io.FileInputStream", &["java.io.InputStream"]),
            ("java.io.FileOutputStream", &["java.io.OutputStream"]),
            ("java.io.FilterInputStream", &["java.io.InputStream"]),
            ("java.io.FilterOutputStream", &["java.io.OutputStream"]),
            ("java.io.BufferedInputStream", &["java.io.FilterInputStream"]),
            ("java.io.BufferedOutputStream", &["java.io.FilterOutputStream"]),
            ("java.util.zip.InflaterInputStream", &["java.io.FilterInputStream"]),
            ("java.util.zip.ZipInputStream", &["java.util.zip.InflaterInputStream"]),
            ("java.util.zip.ZipFile", &["java.lang.Object", "java.io.Closeable"]),
            ("java.util.zip.ZipEntry", &["java.lang.Object", "java.lang.Cloneable"]),
            ("java.net.URL", &["java.lang.Object", "java.io.Serializable"]),
            ("java.net.URLConnection", &["java.lang.Object"]),
            ("java.net.HttpURLConnection", &["java.net.URLConnection"]),
            ("javax.net.ssl.HttpsURLConnection", &["java.net.HttpURLConnection"]),
            ("android.content.Context", &["java.lang.Object"]),
            ("android.content.ContextWrapper", &["android.content.Context"]),
            (
                "android.view.ContextThemeWrapper",
                &["android.content.ContextWrapper"],
            ),
            (
                "android.app.Activity",
                &[
                    "android.view.ContextThemeWrapper",
                    "android.view.LayoutInflater$Factory2",
                    "android.view.Window$Callback",
                    "android.view.KeyEvent$Callback",
                    "android.view.View$OnCreateContextMenuListener",
                    "android.content.ComponentCallbacks2",
                ],
            ),
            (
                "android.app.ListActivity",
                &["android.app.Activity"],
            ),
            (
                "android.preference.PreferenceActivity",
                &["android.app.ListActivity"],
            ),
            (
                "android.app.Service",
                &[
                    "android.content.ContextWrapper",
                    "android.content.ComponentCallbacks2",
                ],
            ),
            ("android.app.IntentService", &["android.app.Service"]),
            (
                "android.app.Application",
                &[
                    "android.content.ContextWrapper",
                    "android.content.ComponentCallbacks2",
                ],
            ),
            ("android.content.BroadcastReceiver", &["java.lang.Object"]),
            (
                "android.content.ContentProvider",
                &[
                    "java.lang.Object",
                    "android.content.ComponentCallbacks2",
                ],
            ),
            ("android.content.ContentResolver", &["java.lang.Object"]),
            ("android.content.Intent", &["java.lang.Object", "android.os.Parcelable", "java.lang.Cloneable"]),
            ("android.app.PendingIntent", &["java.lang.Object", "android.os.Parcelable"]),
            ("android.app.Fragment", &["java.lang.Object", "android.content.ComponentCallbacks2", "android.view.View$OnCreateContextMenuListener"]),
            ("android.app.DialogFragment", &["android.app.Fragment", "android.content.DialogInterface$OnCancelListener", "android.content.DialogInterface$OnDismissListener"]),
            ("androidx.fragment.app.Fragment", &["java.lang.Object", "android.content.ComponentCallbacks", "android.view.View$OnCreateContextMenuListener"]),
            ("androidx.core.app.ComponentActivity", &["android.app.Activity"]),
            ("androidx.activity.ComponentActivity", &["androidx.core.app.ComponentActivity"]),
            ("androidx.fragment.app.FragmentActivity", &["androidx.activity.ComponentActivity"]),
            ("androidx.appcompat.app.AppCompatActivity", &["androidx.fragment.app.FragmentActivity"]),
            ("android.os.Bundle", &["android.os.BaseBundle", "java.lang.Cloneable", "android.os.Parcelable"]),
            ("android.os.BaseBundle", &["java.lang.Object"]),
            ("android.os.Handler", &["java.lang.Object"]),
            ("android.os.AsyncTask", &["java.lang.Object"]),
            ("android.os.Binder", &["java.lang.Object", "android.os.IBinder"]),
            (
                "android.view.View",
                &[
                    "java.lang.Object",
                    "android.graphics.drawable.Drawable$Callback",
                    "android.view.KeyEvent$Callback",
                    "android.view.accessibility.AccessibilityEventSource",
                ],
            ),
            (
                "android.view.ViewGroup",
                &[
                    "android.view.View",
                    "android.view.ViewParent",
                    "android.view.ViewManager",
                ],
            ),
            ("android.widget.AbsoluteLayout", &["android.view.ViewGroup"]),
            ("android.webkit.WebView", &["android.widget.AbsoluteLayout", "android.view.ViewTreeObserver$OnGlobalFocusChangeListener", "android.view.ViewGroup$OnHierarchyChangeListener"]),
            ("android.webkit.WebSettings", &["java.lang.Object"]),
            ("android.webkit.WebViewClient", &["java.lang.Object"]),
            ("android.webkit.WebChromeClient", &["java.lang.Object"]),
            ("android.webkit.CookieManager", &["java.lang.Object"]),
            ("android.webkit.ValueCallback", &["java.lang.Object"]),
            ("android.widget.FrameLayout", &["android.view.ViewGroup"]),
            ("android.widget.LinearLayout", &["android.view.ViewGroup"]),
            ("android.widget.RelativeLayout", &["android.view.ViewGroup"]),
            ("android.widget.TextView", &["android.view.View", "android.view.ViewTreeObserver$OnPreDrawListener"]),
            ("android.widget.EditText", &["android.widget.TextView"]),
            ("android.widget.Button", &["android.widget.TextView"]),
            ("android.widget.ImageView", &["android.view.View"]),
            ("android.widget.ImageButton", &["android.widget.ImageView"]),
            ("android.widget.ListView", &["android.widget.AbsListView"]),
            ("android.widget.AbsListView", &["android.widget.AdapterView"]),
            ("android.widget.AdapterView", &["android.view.ViewGroup"]),
            ("android.database.sqlite.SQLiteOpenHelper", &["java.lang.Object", "java.lang.AutoCloseable"]),
            ("android.database.sqlite.SQLiteClosable", &["java.lang.Object", "java.io.Closeable"]),
            ("android.database.sqlite.SQLiteDatabase", &["android.database.sqlite.SQLiteClosable"]),
            ("android.content.ClipboardManager", &["android.text.ClipboardManager"]),
            ("android.text.ClipboardManager", &["java.lang.Object"]),
            ("android.accounts.AccountManager", &["java.lang.Object"]),
            ("javax.crypto.Cipher", &["java.lang.Object"]),
        ];

        for (cls, parents) in parents_table {
            direct_parents.insert(
                (*cls).to_string(),
                parents.iter().map(|s| (*s).to_string()).collect(),
            );
        }

        let methods_table: &[(&str, &[&str])] = &[
            (
                "java.lang.Object",
                &[
                    "<init>", "equals", "hashCode", "toString", "getClass", "clone", "notify",
                    "notifyAll", "wait", "finalize",
                ],
            ),
            (
                "android.content.Context",
                &[
                    "startActivity",
                    "startActivities",
                    "startService",
                    "startForegroundService",
                    "stopService",
                    "bindService",
                    "unbindService",
                    "sendBroadcast",
                    "sendOrderedBroadcast",
                    "registerReceiver",
                    "unregisterReceiver",
                    "getContentResolver",
                    "getSharedPreferences",
                    "openFileInput",
                    "openFileOutput",
                    "deleteFile",
                    "getFileStreamPath",
                    "getFilesDir",
                    "getCacheDir",
                    "getExternalFilesDir",
                    "getExternalCacheDir",
                    "getDatabasePath",
                    "openOrCreateDatabase",
                    "getSystemService",
                    "getString",
                    "getResources",
                    "getAssets",
                    "getPackageName",
                    "getPackageManager",
                    "getApplicationContext",
                    "getApplicationInfo",
                    "getClassLoader",
                    "checkPermission",
                    "checkSelfPermission",
                ],
            ),
            (
                "android.content.ContextWrapper",
                &[
                    "getBaseContext",
                    "attachBaseContext",
                    "startActivity",
                    "startActivities",
                    "startService",
                    "bindService",
                    "sendBroadcast",
                    "getContentResolver",
                    "getSharedPreferences",
                    "getSystemService",
                    "getResources",
                    "getPackageName",
                    "getApplicationContext",
                ],
            ),
            (
                "android.app.Activity",
                &[
                    "onCreate",
                    "onStart",
                    "onRestart",
                    "onResume",
                    "onPause",
                    "onStop",
                    "onDestroy",
                    "onSaveInstanceState",
                    "onRestoreInstanceState",
                    "onActivityResult",
                    "onBackPressed",
                    "onNewIntent",
                    "onCreateOptionsMenu",
                    "onOptionsItemSelected",
                    "onRequestPermissionsResult",
                    "setContentView",
                    "findViewById",
                    "getIntent",
                    "setIntent",
                    "setResult",
                    "finish",
                    "startActivity",
                    "startActivities",
                    "startActivityForResult",
                    "getWindow",
                    "getWindowManager",
                    "getLayoutInflater",
                    "getFragmentManager",
                    "getActionBar",
                    "runOnUiThread",
                ],
            ),
            (
                "android.app.Service",
                &[
                    "onCreate",
                    "onStartCommand",
                    "onBind",
                    "onUnbind",
                    "onRebind",
                    "onDestroy",
                    "stopSelf",
                    "startForeground",
                    "stopForeground",
                ],
            ),
            (
                "android.content.BroadcastReceiver",
                &["onReceive", "getResultCode", "setResultCode", "getResultData", "abortBroadcast"],
            ),
            (
                "android.content.ContentProvider",
                &[
                    "onCreate",
                    "query",
                    "insert",
                    "update",
                    "delete",
                    "getType",
                    "openFile",
                    "call",
                    "getContext",
                ],
            ),
            (
                "android.view.View",
                &[
                    "findViewById",
                    "setOnClickListener",
                    "setVisibility",
                    "getVisibility",
                    "getId",
                    "setId",
                    "getTag",
                    "setTag",
                    "getContext",
                    "getResources",
                    "getPaddingTop",
                    "getPaddingBottom",
                    "getPaddingLeft",
                    "getPaddingRight",
                    "setPadding",
                    "invalidate",
                    "requestLayout",
                    "post",
                    "postDelayed",
                    "onDraw",
                    "onMeasure",
                    "onLayout",
                    "onTouchEvent",
                ],
            ),
            (
                "android.webkit.WebView",
                &[
                    "loadUrl",
                    "postUrl",
                    "loadData",
                    "loadDataWithBaseURL",
                    "evaluateJavascript",
                    "addJavascriptInterface",
                    "removeJavascriptInterface",
                    "getSettings",
                    "setWebViewClient",
                    "setWebChromeClient",
                    "canGoBack",
                    "goBack",
                    "destroy",
                ],
            ),
            (
                "android.webkit.WebViewClient",
                &[
                    "shouldOverrideUrlLoading",
                    "shouldInterceptRequest",
                    "onPageStarted",
                    "onPageFinished",
                    "onReceivedError",
                    "onReceivedSslError",
                ],
            ),
            (
                "android.webkit.WebChromeClient",
                &[
                    "onJsAlert",
                    "onJsConfirm",
                    "onJsPrompt",
                    "onConsoleMessage",
                    "onShowFileChooser",
                    "onProgressChanged",
                ],
            ),
            (
                "android.database.sqlite.SQLiteOpenHelper",
                &[
                    "onCreate",
                    "onUpgrade",
                    "onDowngrade",
                    "onOpen",
                    "getWritableDatabase",
                    "getReadableDatabase",
                    "close",
                ],
            ),
            (
                "java.lang.Runnable",
                &["run"],
            ),
        ];

        for (cls, mths) in methods_table {
            declared_methods.insert(
                (*cls).to_string(),
                mths.iter().map(|s| (*s).to_string()).collect(),
            );
        }

        FrameworkKnowledge {
            direct_parents,
            declared_methods,
        }
    }

    pub fn is_known(&self, class_name: &str) -> bool {
        let norm = class_name.replace('/', ".");
        if self.direct_parents.contains_key(&norm) || self.declared_methods.contains_key(&norm) {
            return true;
        }
        norm.starts_with("java.")
            || norm.starts_with("javax.")
            || norm.starts_with("android.")
            || norm.starts_with("androidx.")
            || norm.starts_with("dalvik.")
            || norm.starts_with("org.json.")
            || norm.starts_with("org.w3c.")
            || norm.starts_with("org.xml.")
    }

    pub fn super_types_of(&self, class_name: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let mut queue = vec![class_name.replace('/', ".")];
        while let Some(curr) = queue.pop() {
            if let Some(parents) = self.direct_parents.get(&curr) {
                for p in parents {
                    if out.insert(p.clone()) {
                        queue.push(p.clone());
                    }
                }
            } else if curr != "java.lang.Object" && self.is_known(&curr) {
                out.insert("java.lang.Object".to_string());
            }
        }
        out
    }

    pub fn declares_method(&self, class_name: &str, bare_method: &str) -> bool {
        self.declared_methods
            .get(class_name)
            .map(|set| set.contains(bare_method))
            .unwrap_or(false)
    }
}
