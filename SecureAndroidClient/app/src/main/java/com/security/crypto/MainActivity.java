package com.security.crypto;

import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.TextView;

import com.security.crypto.Configuration.Properties;
import com.security.crypto.Handshake.SessionHandler;

public class MainActivity extends AppCompatActivity {
    private Context sContext = this;
    private TextView textview;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        if (isNetworkAvailable()) {
            setContentView(R.layout.activity_main);
            textview = (TextView) findViewById(R.id.textview);
            new BackrounOperation(Properties.SslTlsV2).execute("");
        } else {
            AlertDialog.Builder alertDialogBuilder = new AlertDialog.Builder(
                    sContext);
            // set title
            alertDialogBuilder.setTitle("Check your Internet Connection");
            // set dialog message
            alertDialogBuilder
                    .setMessage("Click yes to exit!")
                    .setCancelable(false)
                    .setPositiveButton("Yes", new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int id) {
                            // if this button is clicked, close
                            // current activity
                            MainActivity.this.finish();
                        }
                    })
                    .setNegativeButton("No", new DialogInterface.OnClickListener() {
                        public void onClick(DialogInterface dialog, int id) {
                            // if this button is clicked, just close
                            // the dialog box and do nothing
                            dialog.cancel();
                        }
                    });

            AlertDialog alertDialog = alertDialogBuilder.create();
            alertDialog.show();
        }

    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();

        //noinspection SimplifiableIfStatement
        if (id == R.id.action_settings) {
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    private boolean isNetworkAvailable() {
        ConnectivityManager connectivityManager
                = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        NetworkInfo activeNetworkInfo = connectivityManager.getActiveNetworkInfo();
        return activeNetworkInfo != null && activeNetworkInfo.isConnected();
    }

    private class BackrounOperation extends AsyncTask<String, Void, String> {

        private ProgressDialog progress;
        private String protocol;

        public BackrounOperation(String protocol) {
            this.protocol = protocol;
            progress = new ProgressDialog(sContext);
        }

        @Override
        protected String doInBackground(String... params) {
            sContext = getApplicationContext();
            SessionHandler session = new SessionHandler(Properties.PlainTextConnection, sContext);
            String Receive = null;
            session.StartDHKeyExchange();
            session.SendSecureMessage("hello Server 1");
            Receive = session.ReceiveSecureMessage();
            System.out.println(Receive);
            session.SendSecureMessage("hello Server 2");
            Receive = session.ReceiveSecureMessage();
            System.out.println(Receive);
            session.ConnectionClose();
            return "Executed " + Receive;
        }

        @Override
        protected void onPreExecute() {
            progress.setTitle("Processing The Message");
            progress.setMessage("Please wait...");
            progress.setCancelable(false);
            progress.setIndeterminate(true);
            progress.show();
        }

        @Override
        protected void onPostExecute(String result) {
            try {
                if (progress.isShowing()) {
                    progress.dismiss();
                    textview.setText(result);
                }
            } catch (Exception e) {
            }
        }

    }
}
