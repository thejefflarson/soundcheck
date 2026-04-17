// GraphQL security — intentionally vulnerable. DO NOT deploy.
const { ApolloServer } = require("@apollo/server");
const { startStandaloneServer } = require("@apollo/server/standalone");

const typeDefs = `#graphql
  type User {
    id: ID!
    name: String!
    posts: [Post!]!
    friends: [User!]!
  }
  type Post {
    id: ID!
    body: String!
    author: User!
    comments: [Comment!]!
  }
  type Comment {
    id: ID!
    text: String!
    author: User!
  }
  type Query {
    user(id: ID!): User
    users: [User!]!
  }
  type Mutation {
    login(email: String!, password: String!): String
  }
`;

// BUG: no depth limit — attacker sends { user { friends { friends { friends { ... } } } } }
// BUG: no cost analysis — alias batching bypasses rate limits
// BUG: introspection enabled in production — full schema exposed
const server = new ApolloServer({
  typeDefs,
  resolvers: {},
  introspection: true, // should be false in production
  // Missing: depthLimit, costAnalysis, alias limits
});

startStandaloneServer(server, { listen: { port: 4000 } });
