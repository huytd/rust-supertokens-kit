-- Create sessions table
CREATE TABLE sessions (
    id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
    user_id UUID REFERENCES users(id) NOT NULL,
    created_at timestamp DEFAULT NOW(),
    expires_at timestamp
)
