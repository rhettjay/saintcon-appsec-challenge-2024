package community.saintcon.appsec;

import community.saintcon.appsec.model.Room;
import community.saintcon.appsec.model.User;
import community.saintcon.appsec.model.UserWithPassword;
import community.saintcon.appsec.utils.AuthUtil;
import community.saintcon.appsec.utils.CryptoUtil;
import community.saintcon.appsec.utils.DbService;
import community.saintcon.appsec.utils.JwtUtil;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.ArrayList;
import java.util.Set;

@CrossOrigin(originPatterns={"http://localhost:[*]", "http://irc.local:[*]"}, allowedHeaders="*", allowCredentials="true")
@RestController
public class ApiController {
    @Autowired
    private DbService dbService;

    @Autowired
    private CryptoUtil cryptoUtil;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private AuthUtil authUtil;

    @GetMapping("/")
    public String index() {
        return "Greetings from Spring Boot!";
    }

    @PostMapping(path = "/login",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> authenticate(@RequestBody Entities.AuthenticationRequest authRequest, HttpServletResponse response) {
        UserWithPassword userWithPassword = dbService.getUserWithPassword(authRequest.username());
        if (userWithPassword == null || !cryptoUtil.comparePassword(authRequest.password(), userWithPassword.password()) || userWithPassword.banned()) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        authUtil.setAuthenticatedUser(response, userWithPassword.userId());
        return new ResponseEntity<>(userWithPassword.toUser(), HttpStatus.OK);
    }

    @PostMapping(path = "/users",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> register(@RequestBody Entities.RegisterRequest registerRequest, HttpServletResponse response) {
        User user = dbService.createUser(registerRequest.name(), registerRequest.username(), cryptoUtil.hashPassword(registerRequest.password()));
        if (user == null) {
            return new ResponseEntity<>(HttpStatus.CONFLICT);
        }
        authUtil.setAuthenticatedUser(response, user.userId());
        return new ResponseEntity<>(user, HttpStatus.CREATED);
    }

    @GetMapping(path="/users/me")
    public ResponseEntity<Object> getMe(HttpServletRequest request) {
        User user = authUtil.getAuthenticatedUser(request);
        if (user == null) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        return new ResponseEntity<>(user, HttpStatus.OK);
    }

    @GetMapping(path = "/users/{id}",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> getUser(HttpServletRequest request, @PathVariable("id") long userId) {
        User user = dbService.getUser(userId);
        User authUser = authUtil.getAuthenticatedUser(request);
        if (user == null || authUser == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        Set<Long> usersInMyRooms = dbService.getUsersInSameRoomsAs(authUser.userId());

        // could put vuln here easy
        if (userId == authUser.userId() || usersInMyRooms.contains(user.userId())) {
            return new ResponseEntity<>(user, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }
    }

    @PutMapping(path = "/users/{id}",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> updateUser(@RequestBody Entities.UpdateUserRequest updateUserRequest, HttpServletRequest request, @PathVariable("id") long userId) {
        UserWithPassword user = authUtil.getAuthenticatedUserWithPassword(request);
        if (user == null) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        } else if (user.userId() != userId) {
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }
        User updatedUser = dbService.updateUser(user, updateUserRequest);
        return new ResponseEntity<>(updatedUser, HttpStatus.CREATED);
    }

    @GetMapping(path = "/rooms",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> getRooms(HttpServletRequest request) {
        User authUser = authUtil.getAuthenticatedUser(request);
        if (authUser == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        ArrayList<Room> rooms = dbService.getRoomsForUser(authUser.userId());
        return new ResponseEntity<>(rooms, HttpStatus.OK);
    }

    @PostMapping(path = "/rooms",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> createRoom(@RequestBody Entities.CreateRoomRequest createRoomRequest, HttpServletRequest request) {
        User user = authUtil.getAuthenticatedUser(request);
        if (user == null) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        Room room = dbService.createRoom(createRoomRequest.name(), user.userId());
        return new ResponseEntity<>(room, HttpStatus.CREATED);
    }

    @GetMapping(path = "/rooms/{id}",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> getRoom(HttpServletRequest request, @PathVariable("id") long roomId) {
        Room room = dbService.getRoom(roomId);
        User authUser = authUtil.getAuthenticatedUser(request);
        if (room == null || authUser == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        Set<Long> usersInRoom = dbService.getUsersInRoom(roomId);

        if (usersInRoom.contains(authUser.userId()) || room.hostId() == authUser.userId()) {
            return new ResponseEntity<>(room, HttpStatus.OK);
        } else {
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }
    }

    @PutMapping(path = "/rooms/{id}",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> updateRoom(@RequestBody Entities.UpdateRoomRequest updateRoomRequest, HttpServletRequest request, @PathVariable("id") long roomId) {
        User user = authUtil.getAuthenticatedUser(request);
        if (user == null) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }

        // check that user is the host of the room
        Room room = dbService.getRoom(roomId);
        if (room == null || room.hostId() != user.userId()) {
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }

        Room newRoom = dbService.updateRoom(roomId, updateRoomRequest.name(), updateRoomRequest.hostId());
        return new ResponseEntity<>(newRoom, HttpStatus.CREATED);
    }

    @GetMapping(path = "/rooms/{id}/users",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> getUsersInRoom(HttpServletRequest request, @PathVariable("id") long roomId) {
        User user = authUtil.getAuthenticatedUser(request);
        if (user == null) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        long roomOwner = dbService.getRoom(roomId).hostId();
        Set<Long> roomMembers = dbService.getUsersInRoom(roomId);
        if (roomOwner != user.userId() && !roomMembers.contains(user.userId())) {
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }
        Set<Long> userIds = dbService.getUsersInRoom(roomId);
        userIds.add(roomOwner);
        ArrayList<User> users = dbService.getUsers(userIds);
        return new ResponseEntity<>(users, HttpStatus.OK);
    }

    @PostMapping(path = "/rooms/{id}/users",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> addUserToRoom(@RequestBody Entities.AddUserToRoomRequest addUserToRoomRequest, HttpServletRequest request, @PathVariable("id") long roomId) {
        User user = authUtil.getAuthenticatedUser(request);
        if (user == null) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        long roomOwner = dbService.getRoom(roomId).hostId();
        if (roomOwner != user.userId()) {
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }
        User newUser = dbService.getUser(addUserToRoomRequest.username());
        if (newUser == null) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        Long userId = dbService.addUserToRoom(newUser.userId(), roomId);
        if (userId == null || userId != newUser.userId()) {
            return new ResponseEntity<>(HttpStatus.CONFLICT);
        }
        return new ResponseEntity<>(newUser, HttpStatus.CREATED);
    }

    @DeleteMapping(path = "/rooms/{roomId}/users/{userId}",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> removeUserFromRoom(HttpServletRequest request, @PathVariable("roomId") long roomId, @PathVariable("userId") long userId) {
        User user = authUtil.getAuthenticatedUser(request);
        if (user == null) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        long roomOwner = dbService.getRoom(roomId).hostId();
        if (roomOwner != user.userId()) {
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }
        if (!dbService.getUsersInRoom(roomId).contains(userId)) {
            return new ResponseEntity<>(HttpStatus.NOT_FOUND);
        }
        boolean success = dbService.removeUserFromRoom(userId, roomId);
        if (!success) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @DeleteMapping(path = "/rooms/{roomId}",
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> deleteRoom(HttpServletRequest request, @PathVariable("roomId") long roomId) {
        User user = authUtil.getAuthenticatedUser(request);
        if (user == null) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        long roomOwner = dbService.getRoom(roomId).hostId();
        if (roomOwner != user.userId()) {
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }
        boolean success = dbService.deleteRoom(roomId);
        if (!success) {
            return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
        }
        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @GetMapping(path="/connect/{roomId}")
    public ResponseEntity<Object> connect(HttpServletRequest request, @PathVariable("roomId") long roomId) {
        User user = authUtil.getAuthenticatedUser(request);
        if (user == null) {
            return new ResponseEntity<>(HttpStatus.UNAUTHORIZED);
        }
        long roomOwner = dbService.getRoom(roomId).hostId();
        Set<Long> roomMembers = dbService.getUsersInRoom(roomId);
        if (roomOwner != user.userId() && !roomMembers.contains(user.userId())) {
            return new ResponseEntity<>(HttpStatus.FORBIDDEN);
        }
        String token = jwtUtil.generateToken(roomId, 1, "R");
        return new ResponseEntity<>(token, HttpStatus.OK);
    }
}
