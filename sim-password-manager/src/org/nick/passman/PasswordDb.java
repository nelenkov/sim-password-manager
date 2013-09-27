package org.nick.passman;

import java.util.ArrayList;
import java.util.List;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

public class PasswordDb extends SQLiteOpenHelper {

    private static final String ID = "_id";
    private static final String NAME = "name";
    private static final String PASSWORD = "password";

    private static final int DATABASE_VERSION = 1;

    private static final String DATABASE_NAME = "passwords.db";

    private static final String PASSWORDS_TABLE_NAME = "passwords";

    public static final String[] ALL_COLUMNS = { ID, NAME, PASSWORD };

    private static final String PASSWORDS_TABLE_CREATE = "create table "
            + PASSWORDS_TABLE_NAME
            + " (_id integer primary key autoincrement, name text not null, "
            + "password text not null);";

    private static PasswordDb instance;

    public static PasswordDb getInstance(Context context) {
        if (instance == null) {
            instance = new PasswordDb(context.getApplicationContext());
        }

        return instance;
    }

    private PasswordDb(Context context) {
        super(context.getApplicationContext(), DATABASE_NAME, null,
                DATABASE_VERSION);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.beginTransaction();
        try {
            db.execSQL(PASSWORDS_TABLE_CREATE);
            db.setTransactionSuccessful();
        } finally {
            db.endTransaction();
        }
    }

    public synchronized long addPasswrod(PasswordEntry entry) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(NAME, entry.getName());
        values.put(PASSWORD, entry.getEncryptedPasswod());

        return db.insertOrThrow(PASSWORDS_TABLE_NAME, null, values);
    }

    public synchronized Cursor getAllPasswordsCursor() {
        SQLiteDatabase db = getReadableDatabase();
        Cursor result = db.query(PASSWORDS_TABLE_NAME, ALL_COLUMNS, null, null,
                null, null, "_id asc");

        return result;
    }

    public synchronized List<PasswordEntry> getAllPasswords() {
        List<PasswordEntry> result = new ArrayList<PasswordEntry>();
        Cursor c = null;
        try {
            c = getAllPasswordsCursor();
            while (c.moveToNext()) {
                long id = c.getLong(c.getColumnIndex(ID));
                String name = c.getString(c.getColumnIndex(NAME));
                String password = c.getString(c.getColumnIndex(PASSWORD));
                PasswordEntry entry = new PasswordEntry(name, password);
                entry.setId(id);

                result.add(entry);
            }

            return result;
        } finally {
            if (c != null) {
                c.close();
            }
        }
    }

    public synchronized void deleteAll() {
        getWritableDatabase().delete(PASSWORDS_TABLE_NAME, null, null);
    }

    @Override
    public void onUpgrade(SQLiteDatabase arg0, int arg1, int arg2) {
    }

}
