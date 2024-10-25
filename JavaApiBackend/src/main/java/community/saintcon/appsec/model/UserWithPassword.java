package community.saintcon.appsec.model;

public record UserWithPassword(long userId, String name, String username, String password, boolean banned) {
    public User toUser() {
        return new User(userId, name, username, banned);
    }
}
