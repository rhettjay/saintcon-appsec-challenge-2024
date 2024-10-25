CREATE TABLE IF NOT EXISTS users (
    id int GENERATED ALWAYS AS IDENTITY UNIQUE,
    username varchar(255) NOT NULL UNIQUE,
    name varchar(255) NOT NULL,
    password_hash varchar(255) NOT NULL,
    banned boolean NOT NULL DEFAULT FALSE,
    role varchar(255) NOT NULL DEFAULT 'user',
    CONSTRAINT chk_role CHECK (role IN ('admin', 'user', 'moderator'))
);
CREATE TABLE IF NOT EXISTS rooms (
    id int GENERATED ALWAYS AS IDENTITY UNIQUE,
    name varchar(255) NOT NULL,
    host int NOT NULL,
    CONSTRAINT fk_rooms FOREIGN KEY (host) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS room_members (
    user_id int REFERENCES users(id) ON DELETE CASCADE,
    room_id int REFERENCES rooms(id) ON DELETE CASCADE
);