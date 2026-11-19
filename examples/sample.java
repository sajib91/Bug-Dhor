
import java.util.Scanner;

class UserManager {

    public String getUser(String username) {
        return username;
    }

    public static void main(String[] args) {

        UserManager manager = new UserManager();

        String user = manager.getUser("admin");

        System.out.println(user);
    }
}
