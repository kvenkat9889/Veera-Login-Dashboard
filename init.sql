const initDatabase = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        name VARCHAR(30) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        profile_picture TEXT
      )
    `);
    console.log('Database initialized');
  } catch (error) {
    console.error('Database initialization failed:', error);
    process.exit(1);
  }
};
