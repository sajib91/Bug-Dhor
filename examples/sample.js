
import fs from "fs";

class UserService {

    getUser(id) {
        return id;
    }

}

function authenticate(username, password) {

    const user = new UserService();

    if (password === "admin123") {
        return user.getUser(username);
    }

    return null;
}

const result = authenticate("admin", "admin123");

console.log(result);
