const express = require('express');
const { auth, requiresAuth } = require('express-openid-connect');
const dotenv = require('dotenv');
const { PrismaClient } = require('@prisma/client');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');


dotenv.config();

const prisma = new PrismaClient();
const app = express();

const config = {
  authRequired: false,
  auth0Logout: true,
  secret: process.env.JWT_SECRET,
  baseURL: process.env.BASE_URL || 'http://localhost:3000',
  clientID: process.env.AUTH0_CLIENT_ID,
  issuerBaseURL: `https://${process.env.AUTH0_DOMAIN}`,
  clientSecret: process.env.AUTH0_CLIENT_SECRET,
  idpLogout: true, // Optional but recommended
};

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'a long, randomly-generated string stored in env',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } // Set to true if using HTTPS
}));

app.use(auth(config));

// Middleware to handle JWT and user role
const jwtMiddleware = (req, res, next) => {
  if (req.oidc && req.oidc.user) {
    req.user = req.oidc.user;
  }
  next();
};

app.use(jwtMiddleware);



app.get('/login', (req, res) => {
  res.oidc.login({ returnTo: '/' });
});

app.get('/', requiresAuth(), async (req, res) => {
  const { user } = req.oidc;

  if(!user){
    res.redirect('/login');
  }
  
  console.log('User in callback:', user);

  let existingUser = await prisma.user.findUnique({ where: { auth0Id: user.sub } });

  if (!existingUser) {
    existingUser = await prisma.user.create({
      data: {
        auth0Id: user.sub,
        email: user.email,
        role: 'USER' // Default role
      }
    });
  }

  if (!existingUser.paypal) {
    // Redirect to signup page to add PayPal details
    res.redirect('/signup');
  } else {
    res.redirect('/profile');
  }
});

app.get('/signup', requiresAuth(), (req, res) => {
  res.sendFile(path.join(__dirname, 'signup.html'));
});

app.post('/signup', requiresAuth(), async (req, res) => {
  const { paypal } = req.body;
  const { user } = req.oidc;

  const updatedUser = await prisma.user.update({
    where: { auth0Id: user.sub },
    data: { paypal }
  });

  res.redirect('/profile');
});

app.get('/profile', requiresAuth(), async (req, res) => {
  const { user } = req.oidc;
  const profile = await prisma.user.findUnique({
    where: { auth0Id: user.sub },
    select: { id: true, email: true, role: true, paypal: true }
  });
  res.json(profile);
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

