package community.saintcon.appsec.utils;

import java.io.*;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import community.saintcon.appsec.Entities;
import community.saintcon.appsec.model.Room;
import community.saintcon.appsec.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;

@Service
public class DbService {

    @Value("${spring.datasource.url}")
    private String DB_URL;
    @Value("${spring.datasource.username}")
    private String DB_USER;
    private final String dbPassword;

    @Autowired
    private CryptoUtil cryptoUtil;

    public DbService() throws IOException {
        this.dbPassword = readPasswordFromFile();
    }

    private String readPasswordFromFile() throws IOException {
        BufferedReader br = new BufferedReader(new FileReader("/run/secrets/postgres_password"));
        return br.readLine();
    }

    private User userParser(ResultSet rs) throws SQLException {
        long id = rs.getLong("id");
        String name = rs.getString("name");
        String username = rs.getString("username");
        String password = rs.getString("password_hash");
        boolean banned = rs.getBoolean("banned");
        return new User(id, name, username, password, banned);
    }

    private Room roomParser(ResultSet rs) throws SQLException {
        long id = rs.getLong("id");
        String name = rs.getString("name");
        long host = rs.getLong("host");
        return new Room(id, name, host);
    }

    public User getUser(String username) {
        ArrayList<User> results = executeQuery(
                (conn) -> {
                    PreparedStatement statement = conn.prepareStatement("SELECT id, name, username, password_hash, banned FROM users WHERE username=?");
                    statement.setString(1, username);
                    return statement;
                },
                this::userParser);
        if (results != null && results.size() == 1) {
            return results.get(0);
        }
        return null;
    }

    public User getUser(long userId) {
        ArrayList<User> results = executeQuery(
                (conn) -> {
                    PreparedStatement statement = conn.prepareStatement("SELECT id, name, username, password_hash, banned FROM users WHERE id=?");
                    statement.setLong(1, userId);
                    return statement;
                },
                this::userParser);
        if (results != null && results.size() == 1) {
            return results.get(0);
        }
        return null;
    }

    public ArrayList<User> getUsers(Collection<Long> userIds) {
        if (userIds.isEmpty()) {
            return new ArrayList<User>();
        }
        String joinedIds = userIds.stream().map(Object::toString).collect(Collectors.joining(","));
        return executeQuery(
                (conn) -> conn.prepareStatement(String.format("SELECT id, name, username, password_hash, banned FROM users WHERE id IN (%s)", joinedIds)),
                this::userParser);
    }

    public User createUser(String name, String username, String passwordHash) {
        ArrayList<Long> userIds = executeQuery(
                (conn) -> {
                    PreparedStatement statement = conn.prepareStatement("INSERT INTO users(name, username, password_hash) VALUES (?, ?, ?) RETURNING id");
                    statement.setString(1, name);
                    statement.setString(2, username);
                    statement.setString(3, passwordHash);
                    return statement;
                },
                (resultSet -> resultSet.getLong("id")));
        if (userIds != null && !userIds.isEmpty()) {
            return new User(userIds.get(0), name, username, passwordHash, false);
        }
        return null;
    }

    public Room createRoom(String name, long hostId) {
        ArrayList<Long> roomIds = executeQuery(
                (conn) -> {
                    PreparedStatement statement = conn.prepareStatement("INSERT INTO rooms(name, host) VALUES (?, ?) RETURNING id");
                    statement.setString(1, name);
                    statement.setLong(2, hostId);
                    return statement;
                },
                (resultSet -> {
                    try {
                        return resultSet.getLong("id");
                    } catch (SQLException e) {
                        return null;
                    }
                }));
        if (roomIds != null && !roomIds.isEmpty()) {
            return new Room(roomIds.get(0), name, hostId);
        }
        return null;
    }

    public User updateUser(User user, Entities.UpdateUserRequest updateUserRequest) {
        String password = updateUserRequest.password() == null ? user.password() : cryptoUtil.hashPassword(updateUserRequest.password());
        String name = updateUserRequest.name() == null ? user.name() : updateUserRequest.name();
        String username = updateUserRequest.username() == null ? user.username() : updateUserRequest.username();
        ArrayList<User> users = executeQuery(
                (conn) -> {
                    PreparedStatement statement = conn.prepareStatement("UPDATE users SET name=?, username=?, password_hash=? WHERE id=? RETURNING id, name, username, password_hash");
                    statement.setString(1, name);
                    statement.setString(2, username);
                    statement.setString(3, password);
                    statement.setLong(4, user.userId());
                    return statement;
                },
                this::userParser);
        if (user != null && !users.isEmpty()) {
            return users.get(0);
        }
        return null;
    }

    public Room getRoom(long roomId) {
        ArrayList<Room> results = executeQuery(
                (conn) -> {
                    PreparedStatement statement = conn.prepareStatement("SELECT id, name, host FROM rooms WHERE id=?");
                    statement.setLong(1, roomId);
                    return statement;
                },
                this::roomParser);
        if (results != null && results.size() == 1) {
            return results.get(0);
        }
        return null;
    }

    public Room updateRoom(long roomId, String name, long hostId) {
        ArrayList<Room> rooms = executeQuery(
                (conn) -> {
                    PreparedStatement statement = conn.prepareStatement("UPDATE rooms SET name=?, host=? WHERE id=? RETURNING id, name, host");
                    statement.setString(1, name);
                    statement.setLong(2, hostId);
                    statement.setLong(3, roomId);
                    return statement;
                },
                this::roomParser);
        if (rooms != null && !rooms.isEmpty()) {
            return rooms.get(0);
        }
        return null;
    }

    public Set<Long> getUsersInRoom(long roomId) {
        return executeQuery(
                (conn) -> {
                    PreparedStatement statement = conn.prepareStatement("SELECT user_id FROM room_members WHERE room_id=?");
                    statement.setLong(1, roomId);
                    return statement;
                },
                (resultSet -> resultSet.getLong("user_id"))
        ).stream().filter(Objects::nonNull).collect(Collectors.toSet());
    }

    public Set<Long> getUsersInSameRoomsAs(long userId) {
        return executeQuery(
                (conn) -> {
                    PreparedStatement statement = conn.prepareStatement("""
                            SELECT DISTINCT(user_id)
                            FROM room_members
                            WHERE room_id IN (
                                SELECT room_id
                                FROM room_members
                                WHERE user_id=?
                                UNION SELECT id as room_id
                                FROM rooms
                                WHERE host=?
                            ) AND user_id != ?;
                            """);
                    statement.setLong(1, userId);
                    statement.setLong(2, userId);
                    statement.setLong(3, userId);
                    return statement;
                },
                (resultSet -> resultSet.getLong("user_id"))
        ).stream().filter(Objects::nonNull).collect(Collectors.toSet());
    }

    public ArrayList<Room> getRoomsForUser(long userId) {
        return executeQuery(
                (conn) -> {
                    PreparedStatement statement = conn.prepareStatement("""
                            SELECT rooms.id, rooms.name, rooms.host
                            FROM room_members
                            INNER JOIN rooms
                            ON room_members.room_id = rooms.id
                            WHERE user_id=?
                            UNION
                            SELECT id, name, host
                            FROM rooms
                            WHERE host=?
                            """);
                    statement.setLong(1, userId);
                    statement.setLong(2, userId);
                    return statement;
                },
                this::roomParser);
    }

    public Long addUserToRoom(long userId, long roomId) {
        ArrayList<Long> results = executeQuery(
                (Connection conn) -> {
                    PreparedStatement statement = conn.prepareStatement("INSERT INTO room_members(user_id, room_id) VALUES (?, ?) RETURNING user_id");
                    statement.setLong(1, userId);
                    statement.setLong(2, roomId);
                    return statement;
                },
                (resultSet) -> resultSet.getLong("user_id"));
        if (results != null && !results.isEmpty()) {
            return results.get(0);
        }
        return null;
    }

    public Boolean removeUserFromRoom(long userId, long roomId) {
        ArrayList<Long> results = executeQuery(
                (Connection conn) -> {
                    PreparedStatement statement = conn.prepareStatement("DELETE FROM room_members WHERE user_id=? AND room_id=? RETURNING user_id");
                    statement.setLong(1, userId);
                    statement.setLong(2, roomId);
                    return statement;
                },
                (resultSet) -> resultSet.getLong("user_id"));
        if (results != null && !results.isEmpty()) {
            return results.get(0) == userId;
        }
        return null;
    }

    public Boolean deleteRoom(long roomId) {
        ArrayList<Long> results = executeQuery(
                (Connection conn) -> {
                    PreparedStatement statement = conn.prepareStatement("DELETE FROM rooms WHERE id=? RETURNING id");
                    statement.setLong(1, roomId);
                    return statement;
                },
                (resultSet) -> resultSet.getLong("id"));
        if (results != null && !results.isEmpty()) {
            return results.get(0) == roomId;
        }
        return null;
    }

    @FunctionalInterface
    public interface StatementPreparer {
        PreparedStatement apply(Connection t) throws SQLException;
    }

    @FunctionalInterface
    public interface ResultsParser<T> {
        T apply(ResultSet t) throws SQLException;
    }

    public <T> ArrayList<T> executeQuery(StatementPreparer statementPreparer, ResultsParser<T> resultParser) {
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        ArrayList<T> results = new ArrayList<>();

        try {
            conn = DriverManager.getConnection(DB_URL, DB_USER, dbPassword);
            pstmt = statementPreparer.apply(conn);
            rs = pstmt.executeQuery();
            while (rs.next()) {
                T parsed = resultParser.apply(rs);
                if (parsed != null) {
                    results.add(parsed);
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
            return null;
        } finally {
            // Close resources
            try {
                if (rs != null) rs.close();
                if (pstmt != null) pstmt.close();
                if (conn != null) conn.close();
            } catch (SQLException e) {
                e.printStackTrace();
                return null;
            }
        }
        return results;
    }
}
