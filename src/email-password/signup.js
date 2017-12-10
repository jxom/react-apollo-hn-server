import { fromEvent, FunctionEvent } from 'graphcool-lib';
import { GraphQLClient } from 'graphql-request';
import * as bcrypt from 'bcryptjs';
import * as validator from 'validator';

const SALT_ROUNDS = 10;

export default async event => {
  console.log(event);

  try {
    const graphcool = fromEvent(event);
    const api = graphcool.api('simple/v1');

    const { email, password, username } = event.data;

    if (!validator.isEmail(email)) {
      return { error: 'Not a valid email' };
    }

    // check if email exists already
    const emailExists = await getUserByEmail(api, email).then(r => r.User !== null);
    if (emailExists) {
      return { error: 'Email already in use' };
		}

    // create password hash
    const salt = bcrypt.genSaltSync(SALT_ROUNDS);
    const hash = await bcrypt.hash(password, SALT_ROUNDS);

    // create new user
    const userId = await createGraphcoolUser(api, email, hash, username);

    // generate node token for new User node
    const token = await graphcool.generateNodeToken(userId, 'User');

    return { data: { id: userId, token } };
  } catch (e) {
    console.log(e);
    return { error: 'An unexpected error occured during signup.' };
  }
};

async function getUserByEmail(api, email) {
  const query = `
    query getUserByEmail($email: String!) {
      User(email: $email) {
        id
      }
    }
  `;

  const variables = {
    email
  };

  return api.request(query, variables);
}

async function createGraphcoolUser(api, email, password, username) {
  const mutation = `
    mutation createGraphcoolUser($email: String!, $password: String!, $username: String!) {
      createUser(
				email: $email,
				password: $password,
				username: $username
      ) {
        id
      }
    }
  `;

  const variables = {
    email,
		password,
		username
  };

  return api.request(mutation, variables).then(r => r.createUser.id);
}
