// sample_graphql.js — fixture for Lyseis unit tests

const client = new ApolloClient({
    uri: '/graphql',
    cache: new InMemoryCache(),
});

const GET_USER = gql`
    query GetUser($id: ID!) {
        user(id: $id) {
            id
            email
            role
        }
    }
`;

// IntrospectionQuery for schema exploration
fetch('/graphql', {
    method: 'POST',
    body: JSON.stringify({ query: '{ __schema { types { name } } }' }),
});

const featureFlags = {
    enableAdminPanel: true,
    betaRoute: "/admin-v2/dashboard",
    darkMode: false,
};

window.addEventListener("message", function (event) {
    if (event.origin !== "https://trusted.example.com") return;
    document.getElementById("content").innerHTML = event.data;
});

const allowedOrigins = "*";

// S3 bucket ref
const staticAssets = "https://my-company-assets.s3.eu-west-1.amazonaws.com/uploads/";

//# sourceMappingURL=app.chunk.js.map
