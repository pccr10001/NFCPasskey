package li.power.app.fido.nfcpasskey.model;

import android.content.Context;
import androidx.room.Database;
import androidx.room.Room;
import androidx.room.RoomDatabase;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@Database(entities = {Credential.class, Token.class}, version = 1, exportSchema = false)
public abstract class AppDatabase extends RoomDatabase {
    private static final int NUMBER_OF_THREADS = 4;
    public static final ExecutorService executor = Executors.newFixedThreadPool(NUMBER_OF_THREADS);

    private static volatile AppDatabase INSTANCE;
    public static AppDatabase getDatabase(final Context context) {
        if (INSTANCE == null) {
            synchronized (AppDatabase.class) {
                if (INSTANCE == null) {

                    INSTANCE = Room.databaseBuilder(context.getApplicationContext(), AppDatabase.class, "fido").allowMainThreadQueries().build();
                }
            }
        }
        return INSTANCE;
    }

    public abstract TokenDao getTokenDao();
    public abstract CredentialDao getCredentialDao();

}