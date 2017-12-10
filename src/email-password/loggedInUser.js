import { fromEvent, FunctionEvent } from 'graphcool-lib';
import { GraphQLClient } from 'graphql-request';

export default async event => {
  console.log(event);

  try {
    // no logged in user
    if (!event.context.auth || !event.context.auth.nodeId) {
      return { data: null };
    }

    const userId = event.context.auth.nodeId;
    const graphcool = fromEvent(event);
    const api = graphcool.api('simple/v1');

    // get user by id
    const user = await getUser(api, userId).then(r => r.User);

    // no logged in user
    if (!user || !user.id) {
      return { data: null };
    }

    return { data: { id: user.id } };
  } catch (e) {
    console.log(e);
    return { error: 'An unexpected error occured during authentication.' };
  }
};

async function getUser(api, id) {
  const query = `
    query getUser($id: ID!) {
      User(id: $id) {
        id
      }
    }
  `;

  const variables = {
    id
  };

  return api.request(query, variables);
}
