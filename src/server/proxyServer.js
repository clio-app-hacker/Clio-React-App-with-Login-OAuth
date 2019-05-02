const app = require('express')();
const ApiServer = require('./apiServer');
const config = require('./config.json');
const uuid = require('uuidv4');
const session = require('express-session');

// persists session info between server restarts
const FileStore = require('session-file-store')(session);

//body-parser middleware to body parse the data and add it to the req.body property
const bodyParser = require('body-parser');

// for authentication
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

// for REST 
const axios = require('axios');

// handling encrypted passwords
const bcrypt = require('bcrypt-nodejs');
/*
// use express to handle incomming request
// use simple-oauth2 for oauth
// use axios for passing api requests to app.clio.com
// store tokens on the server so they do not leak on client apps
// handle license key generation and storage
// in memory DB for fast access to already retrieved data
*/
const credentials = {
    client: {
        id: config.id,
        secret: config.secrect
    },
    auth: {
        tokenHost: config.tokenHost
    }
};

// configure passport.js to use the local strategy
passport.use(new LocalStrategy(
    { usernameField: 'email' },
    (email, password, done) => {
        axios.get(`http://localhost:5000/users?email=${email}`)
            .then(res => {
                const user = res.data[0]
                if (!user) {
                    return done(null, false, { message: 'Invalid credentials.\n' });
                }
                if (!bcrypt.compareSync(password, user.password)) {
                    return done(null, false, { message: 'Invalid credentials.\n' });
                }
                return done(null, user);
            })
            .catch(error => done(error));
    }
));

// tell passport how to serialize the user
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    axios.get(`http://localhost:5000/users/${id}`)
        .then(res => done(null, res.data))
        .catch(error => done(error, false))
});

// create oauth instance using credentials
const oauth2 = require('simple-oauth2').create(credentials);

// add & configure session middleware
app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json())
app.use(session({
    genid: (req) => {
        console.log('Inside the session middleware: ', req.sessionID)
        return uuid() // use UUIDs for session IDs
    },
    store: new FileStore(),
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: true
}));
app.use(passport.initialize());
app.use(passport.session());

/**
 * Done route - for testing mostly...
 */
app.get('/done', async (req, res) => {
    console.log('Inside GET /login callback function')
    console.log("Session ID:", req.sessionID)
    res.send(`<pre>Setup done</pre>`);
});

/**
 * Simple route for all /api/v4 get requests
 */
app.get('/api/v4/*', async (req, res) => {
    // console.log("Request:", req);

    const result = await ApiServer.get(req._parsedOriginalUrl.path);
    // console.log("API Server result:", result)
    let json = JSON.stringify(result.data.data, null, 2);
    // console.log("Result:", json);
    res.send(`<pre>${json}</pre>`);
});

/**
 * Initial oauth response which contains the code to use to request
 * an access token.
 * 
 * Note: This code is specific to a user and their env.
 */
app.get('/oauth/response', async (req, res) => {
    console.log("oauth/response: ", req.query.code);

    // use the returned code to get the token
    //  - pass in the required attributes
    //  - redirect_uri has to be the same as the one used in the authorizationUri
    const tokenConfig = {
        client_id: config.id,
        client_secret: config.secrect,
        code: req.query.code,
        grant_type: "authorization_code",
        redirect_uri: config.redirectUri,
    };

    try {
        const result = await oauth2.authorizationCode.getToken(tokenConfig)
        console.log("result:", result);

        // WARNING: This will setup the API server with a single token, hence this only works for 
        //    a single user. If you have multiple users you need to store each token per user on 
        //    the server and retrieve the token for the user when the user makes a request.
        //    Otherwise every user gets to access the first users Data - NOT GOOD !!!!
        ApiServer.initialize(result.access_token);

        // redirect to the application done page
        res.redirect(`http://localhost:${config.proxyPort}/done`);

    } catch (error) {
        console.log('Access Token Error', error);
    }
});

/**
 * OAuth entry point
 */
app.get('/oauth', (req, res) => {
    console.log("oauth");

    // create a authorizationUri using simple-oauth2 library
    const authorizationUri = oauth2.authorizationCode.authorizeURL({
        redirect_uri: config.redirectUri,
    });

    // redirect to 
    res.redirect(authorizationUri);
});

// create the login get and post routes
app.get('/login', (req, res) => {
    console.log('Inside GET /login callback function')
    console.log(req.sessionID)
    res.send(`You got the login page!\n`)
})

app.post('/login', (req, res, next) => {
    console.log('Inside POST /login callback')
    passport.authenticate('local', (err, user, info) => {
        console.log('Inside passport.authenticate() callback');
        console.log(`req.session.passport: ${JSON.stringify(req.session.passport)}`)
        console.log(`req.user: ${JSON.stringify(req.user)}`)
        req.login(user, (err) => {
            console.log('Inside req.login() callback')
            console.log(`req.session.passport: ${JSON.stringify(req.session.passport)}`)
            console.log(`req.user: ${JSON.stringify(req.user)}`)
            return res.send('You were authenticated & logged in!\n');
        })
    })(req, res, next);
})

app.get('/authrequired', (req, res) => {
    console.log('Inside GET /authrequired callback')
    console.log(`User authenticated? ${req.isAuthenticated()}`)
    if (req.isAuthenticated()) {
        res.send('you hit the authentication endpoint\n')
    } else {
        res.redirect('/')
    }
})
/**
 * Catch all...
 */
app.get('/*', (req, res) => {
    res.send(`Unsupported request: ${req._parsedOriginalUrl.path}`)
});

app.listen(config.proxyPort, () => {
    console.log(`Listening on localhost:${config.proxyPort}`)
});
