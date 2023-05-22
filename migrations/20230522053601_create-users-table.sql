-- Enable UUID extension
CREATE EXTENSION "uuid-ossp";

-- Create users table
CREATE TABLE users (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    google_id VARCHAR(255) UNIQUE,
    email VARCHAR(320) UNIQUE,
    name VARCHAR(50),
    picture VARCHAR(255),
    created_at timestamp DEFAULT NOW()
)