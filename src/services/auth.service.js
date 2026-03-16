import { eq } from 'drizzle-orm';
import { db } from '#config/database.js';
import { users } from '#models/user.model.js';
import logger from '#config/logger.js';
import bcrypt from 'bcrypt';
import { jwttoken } from '#utils/jwt.js';

/**
 * Hashes a plain text password using bcrypt
 */
export const hashPassword = async (password) => {
  try {
    return await bcrypt.hash(password, 10);
  } catch (e) {
    logger.error(`Error hashing the password: ${e}`);
    throw new Error('Error hashing', { cause: e },);
  }
};

/**
 * Creates a new user in the database after checking for existence
 */
export const createUser = async ({ name, email, password, role = 'user' }) => {
  try {
    const existingUser = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (existingUser.length > 0) throw new Error('User already exists');

    const password_hash = await hashPassword(password);

    const [newUser] = await db
      .insert(users)
      .values({ name, email, password: password_hash, role })
      .returning({
        id: users.id,
        name: users.name,
        email: users.email,
        role: users.role,
        created_at: users.created_at,
      });

    logger.info(`User ${newUser.email} created successfully`);
    return newUser;
  } catch (e) {
    logger.error(`Error creating the user: ${e}`);
    throw e;
  }
};

/**
 * Finds a user by email and verifies their password
 */
export const signInUser = async ({ email, password }) => {
  try {
    const [existingUser] = await db
      .select()
      .from(users)
      .where(eq(users.email, email))
      .limit(1);

    if (!existingUser) throw new Error('Invalid credentials');

    const isPasswordValid = await bcrypt.compare(password, existingUser.password);
    if (!isPasswordValid) throw new Error('Invalid credentials');

    logger.info(`User ${email} signed in successfully`);
    return {
      id: existingUser.id,
      name: existingUser.name,
      email: existingUser.email,
      role: existingUser.role,
    };
  } catch (e) {
    logger.error(`Error signing in user: ${e}`);
    throw e;
  }
};

/**
 * Verifies the session token before sign-out (extension point for token blacklisting)
 */
export const signOutUser = async (token) => {
  try {
    const payload = jwttoken.verify(token);
    logger.info(`User ${payload.email} signed out`);
    return payload;
  } catch (e) {
    logger.error(`Error signing out user: ${e}`);
    throw e;
  }
};