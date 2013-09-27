package org.nick.passman;

import static org.nick.passman.Hex.toHex;

import java.util.List;

import org.simalliance.openmobileapi.Reader;
import org.simalliance.openmobileapi.SEService;
import org.simalliance.openmobileapi.Session;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Context;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.text.TextUtils;
import android.util.Log;
import android.view.ActionMode;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemLongClickListener;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends Activity implements SEService.CallBack,
        OnClickListener, OnItemLongClickListener {

    private static final String TAG = "SIM Password Manager";

    private SEService seService;

    private TextView messageText;
    private EditText nameText;
    private EditText passwordText;
    private Button initilizeButton;
    private ListView passwordsList;

    private Reader reader;
    private Session session;

    private PmAppletClient pm;
    private PasswordDb db;

    private boolean appletInitialized = false;

    private ActionMode currentActionMode;

    private Handler handler;

    private static class PasswordAdapter extends ArrayAdapter<PasswordEntry> {

        PasswordAdapter(Context context, PasswordEntry[] items) {
            super(context, android.R.layout.select_dialog_item,
                    android.R.id.text1, items);
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            View result = super.getView(position, convertView, parent);
            TextView tv = (TextView) result.findViewById(android.R.id.text1);
            tv.setText(getItem(position).getName());

            return result;
        }

    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);

        setContentView(R.layout.activity_main);

        messageText = (TextView) findViewById(R.id.message_text);
        nameText = (EditText) findViewById(R.id.name_text);
        passwordText = (EditText) findViewById(R.id.password_text);

        initilizeButton = (Button) findViewById(R.id.init_pm_button);
        initilizeButton.setOnClickListener(this);
        initilizeButton.setVisibility(View.GONE);
        initilizeButton.setEnabled(false);

        passwordsList = (ListView) findViewById(R.id.passwords_list);
        passwordsList.setOnItemLongClickListener(this);
        passwordsList.setChoiceMode(ListView.CHOICE_MODE_SINGLE);

        handler = new Handler() {
            @Override
            public void handleMessage(Message msg) {
                nameText.setText(null);
                passwordText.setText(null);
            }

        };

        db = PasswordDb.getInstance(this);
    }

    private void connectToSeService() {
        try {
            Log.i(TAG, "creating SEService object");
            seService = new SEService(this, this);
        } catch (SecurityException e) {
            Log.e(TAG,
                    "Binding not allowed, uses-permission org.simalliance.openmobileapi.SMARTCARD?");
            Toast.makeText(MainActivity.this, e.getMessage(), Toast.LENGTH_LONG)
                    .show();

            finish();
        } catch (Exception e) {
            Log.e(TAG, "Exception: " + e.getMessage());
            Toast.makeText(MainActivity.this, e.getMessage(), Toast.LENGTH_LONG)
                    .show();

            finish();
        }
    }

    @Override
    public boolean onPrepareOptionsMenu(Menu menu) {
        menu.findItem(R.id.action_add).setEnabled(appletInitialized);

        return super.onPrepareOptionsMenu(menu);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public void onResume() {
        super.onResume();

        if (seService == null || !seService.isConnected()) {
            connectToSeService();

            return;
        }

        checkAppletState();
    }

    @Override
    public void onPause() {
        super.onPause();
        passwordText.setText(null);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
        case R.id.action_add:
            addPassword();
            break;
        case R.id.action_clear:
            clear();
            break;
        default:
            // do nothing
        }

        return super.onOptionsItemSelected(item);
    }

    private void addPassword() {
        if (TextUtils.isEmpty(nameText.getText())
                || TextUtils.isEmpty(passwordText.getText())) {
            Toast.makeText(this, "Name and password must not be empty",
                    Toast.LENGTH_SHORT).show();
            return;
        }

        new AsyncTask<Void, Void, Void>() {

            Exception error;

            @Override
            protected void onPreExecute() {
                setProgressBarIndeterminateVisibility(true);
                messageText.setText("");
            }

            @Override
            protected Void doInBackground(Void... arg) {
                try {
                    String encrypted = pm.encryptStr(passwordText.getText()
                            .toString());
                    PasswordEntry entry = new PasswordEntry(nameText.getText()
                            .toString(), encrypted);
                    db.addPasswrod(entry);
                } catch (Exception e) {
                    Log.e(TAG, "Error: " + e.getMessage(), e);
                    error = e;
                } finally {
                    if (pm != null) {
                        pm.disconnect();
                    }
                }

                return null;
            }

            @Override
            protected void onPostExecute(Void result) {
                setProgressBarIndeterminateVisibility(false);

                if (error != null) {
                    Toast.makeText(MainActivity.this, error.getMessage(),
                            Toast.LENGTH_LONG).show();

                    return;
                }

                nameText.setText(null);
                passwordText.setText(null);

                loadPasswords();
            }

        }.execute();
    }

    private void loadPasswords() {
        new AsyncTask<Void, Void, List<PasswordEntry>>() {

            Exception error;

            @Override
            protected void onPreExecute() {
                setProgressBarIndeterminateVisibility(true);
            }

            @Override
            protected List<PasswordEntry> doInBackground(Void... arg0) {
                try {
                    return db.getAllPasswords();
                } catch (Exception e) {
                    Log.e(TAG, "Error: " + e.getMessage(), e);
                    error = e;
                }

                return null;
            }

            @Override
            protected void onPostExecute(List<PasswordEntry> result) {
                setProgressBarIndeterminateVisibility(false);
                if (error != null) {
                    Toast.makeText(MainActivity.this,
                            "Error loading passwords: " + error.getMessage(),
                            Toast.LENGTH_LONG).show();

                    return;
                }

                PasswordEntry[] passwords = new PasswordEntry[result.size()];
                result.toArray(passwords);

                PasswordAdapter adapter = new PasswordAdapter(
                        MainActivity.this, passwords);
                passwordsList.setAdapter(adapter);
            }
        }.execute();
    }

    private void clear() {
        new AsyncTask<Void, Void, Void>() {

            Exception error;

            @Override
            protected void onPreExecute() {
                setProgressBarIndeterminateVisibility(true);
            }

            @Override
            protected Void doInBackground(Void... arg0) {
                try {
                    if (session == null) {
                        session = reader.openSession();
                    }
                    try {
                        if (pm == null) {
                            pm = new PmAppletClient(session);
                        }
                        appletInitialized = pm.isInitialized();
                        Log.d(TAG, "initialized: " + appletInitialized);
                        pm.clear();
                        appletInitialized = pm.isInitialized();

                        db.deleteAll();
                    } finally {
                        if (pm != null) {
                            pm.disconnect();
                        }
                    }
                } catch (Exception e) {
                    Log.e(TAG, "Error: " + e.getMessage(), e);
                    error = e;
                }

                return null;
            }

            @Override
            protected void onPostExecute(Void result) {
                setProgressBarIndeterminateVisibility(false);

                if (error != null) {
                    Toast.makeText(
                            MainActivity.this,
                            "Error clearing applet state: "
                                    + error.getMessage(), Toast.LENGTH_LONG)
                            .show();

                    return;
                }

                toggleUi();

                loadPasswords();
            }
        }.execute();
    }

    private void toggleUi() {
        messageText.setText(appletInitialized ? "Connected"
                : "Applet not initialized");

        messageText.setVisibility(View.VISIBLE);
        nameText.setVisibility(appletInitialized ? View.VISIBLE
                : View.INVISIBLE);
        passwordText.setVisibility(appletInitialized ? View.VISIBLE
                : View.INVISIBLE);

        initilizeButton.setVisibility(appletInitialized ? View.GONE
                : View.VISIBLE);
        initilizeButton.setEnabled(!appletInitialized);

        invalidateOptionsMenu();
    }

    @Override
    protected void onDestroy() {
        if (reader != null) {
            reader.closeSessions();
        }
        if (seService != null && seService.isConnected()) {
            seService.shutdown();
        }
        super.onDestroy();
    }

    public void serviceConnected(SEService service) {
        Log.i(TAG, "seviceConnected()");

        Reader[] readers = seService.getReaders();
        if (readers.length < 1) {
            Toast.makeText(this, "No readers found", Toast.LENGTH_SHORT).show();
            return;
        }

        for (Reader r : readers) {
            if (r.isSecureElementPresent()) {
                reader = r;
                break;
            }
        }

        if (reader == null) {
            Toast.makeText(this, "No SEs found", Toast.LENGTH_LONG).show();
            finish();

            return;
        }

        new AsyncTask<Void, Void, Void>() {

            Exception error;

            @Override
            protected void onPreExecute() {
                setProgressBarIndeterminateVisibility(true);
            }

            @Override
            protected Void doInBackground(Void... arg0) {
                try {
                    session = reader.openSession();
                    if (session.getATR() != null) {
                        Log.d(TAG, "ATR " + toHex(session.getATR()));
                    }

                    try {
                        pm = new PmAppletClient(session);
                        appletInitialized = pm.isInitialized();
                        Log.d(TAG, "initialized: " + appletInitialized);
                    } finally {
                        if (pm != null) {
                            pm.disconnect();
                        }
                    }
                } catch (Exception e) {
                    Log.e(TAG, "Error: " + e.getMessage(), e);
                    error = e;
                }

                return null;
            }

            @Override
            protected void onPostExecute(Void result) {
                setProgressBarIndeterminateVisibility(false);

                if (error != null) {
                    Toast.makeText(
                            MainActivity.this,
                            "Error checking applet state: "
                                    + error.getMessage(), Toast.LENGTH_LONG)
                            .show();

                    return;
                }

                toggleUi();

                loadPasswords();
            }
        }.execute();

    }

    private void checkAppletState() {
        appletInitialized = false;
        toggleUi();

        new AsyncTask<Void, Void, Void>() {

            Exception error;

            @Override
            protected void onPreExecute() {
                setProgressBarIndeterminateVisibility(true);
            }

            @Override
            protected Void doInBackground(Void... arg0) {
                try {
                    try {
                        if (pm == null) {
                            pm = new PmAppletClient(session);
                        }
                        appletInitialized = pm.isInitialized();
                        Log.d(TAG, "initialized: " + appletInitialized);
                    } finally {
                        if (pm != null) {
                            pm.disconnect();
                        }
                    }
                } catch (Exception e) {
                    Log.e(TAG, "Error: " + e.getMessage(), e);
                    error = e;
                }

                return null;
            }

            @Override
            protected void onPostExecute(Void result) {
                setProgressBarIndeterminateVisibility(false);

                if (error != null) {
                    Toast.makeText(
                            MainActivity.this,
                            "Error checking applet state: "
                                    + error.getMessage(), Toast.LENGTH_LONG)
                            .show();

                    return;
                }

                toggleUi();

                loadPasswords();
            }
        }.execute();
    }

    @Override
    public void onClick(View v) {
        switch (v.getId()) {
        case R.id.init_pm_button:
            initializeApplet();
            break;
        }
    }

    private void initializeApplet() {
        new AsyncTask<Void, Void, Void>() {

            Exception error;

            @Override
            protected void onPreExecute() {
                setProgressBarIndeterminateVisibility(true);
                initilizeButton.setEnabled(false);
                messageText.setText("Initializing...");
            }

            @Override
            protected Void doInBackground(Void... arg) {
                try {
                    appletInitialized = pm.isInitialized();
                    Log.d(TAG, "initialized: " + appletInitialized);

                    if (!appletInitialized) {
                        Log.d(TAG, "generating keys...");
                        long start = System.currentTimeMillis();
                        pm.generateKeys();
                        Log.d(TAG,
                                String.format("Done: %d[ms]",
                                        (System.currentTimeMillis() - start)));
                    }
                    appletInitialized = pm.isInitialized();
                } catch (Exception e) {
                    Log.e(TAG, "Error: " + e.getMessage(), e);
                    error = e;
                } finally {
                    if (pm != null) {
                        pm.disconnect();
                    }
                }

                return null;
            }

            @Override
            protected void onPostExecute(Void result) {
                setProgressBarIndeterminateVisibility(false);

                if (error != null) {
                    Toast.makeText(MainActivity.this, error.getMessage(),
                            Toast.LENGTH_LONG).show();

                    return;
                }

                toggleUi();
            }

        }.execute();
    }

    @Override
    public boolean onItemLongClick(AdapterView<?> parent, View view,
            int position, long id) {
        if (currentActionMode != null) {
            return false;
        }

        currentActionMode = startActionMode(new ContextCallback(position));
        passwordsList.setItemChecked(position, true);

        return true;
    }

    @SuppressLint("NewApi")
    class ContextCallback implements ActionMode.Callback {

        private int position;

        ContextCallback(int position) {
            this.position = position;
        }

        public boolean onCreateActionMode(ActionMode actionMode, Menu menu) {
            MenuInflater inflater = getMenuInflater();
            inflater.inflate(R.menu.context, menu);
            return true;
        }

        public boolean onPrepareActionMode(ActionMode actionMode, Menu menu) {
            return false;
        }

        public boolean onActionItemClicked(ActionMode actionMode,
                MenuItem menuItem) {
            if (menuItem.getItemId() == R.id.action_show) {
                showPassword(position);
                actionMode.finish();
                return true;
            }

            return false;
        }

        public void onDestroyActionMode(ActionMode actionMode) {
            passwordsList.setItemChecked(position, false);
            currentActionMode = null;
        }
    }

    public void showPassword(int position) {
        final PasswordEntry entry = (PasswordEntry) passwordsList.getAdapter()
                .getItem(position);

        new AsyncTask<Void, Void, String>() {

            Exception error;

            @Override
            protected void onPreExecute() {
                setProgressBarIndeterminateVisibility(true);
                messageText.setText("");
            }

            @Override
            protected String doInBackground(Void... arg) {
                try {
                    return pm.decryptStr(entry.getEncryptedPasswod());
                } catch (Exception e) {
                    Log.e(TAG, "Error: " + e.getMessage(), e);
                    error = e;
                } finally {
                    if (pm != null) {
                        pm.disconnect();
                    }
                }

                return null;
            }

            @Override
            protected void onPostExecute(String password) {
                setProgressBarIndeterminateVisibility(false);

                if (error != null) {
                    Toast.makeText(MainActivity.this, error.getMessage(),
                            Toast.LENGTH_LONG).show();

                    return;
                }

                nameText.setText(entry.getName());
                passwordText.setText(password);
                passwordText.requestFocus();
                passwordText.selectAll();

                // clear after 15 secs
                Message msg = Message.obtain(handler);
                handler.sendMessageDelayed(msg, 15 * 1000);
            }

        }.execute();
    }

}
