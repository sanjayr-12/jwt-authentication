const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");

app.use(express.json());

const users = [
  {
    id: "1",
    username: "john",
    password: "john123",
    isAdmin: true,
  },
  {
    id: "2",
    username: "jane",
    password: "jane123",
    isAdmin: false,
  },
];

//refresh token
//if the token expires the refresh token generates the new token

let refreshTokens = [];

app.post("/api/refresh", (req, res) => {
  //take the token from the user
  const refreshToken = req.body.token;

  //send the error if there is no token and the token is not valid
  if (!refreshToken) {
    return res.status(401).json("you are not authenticated");
  }
  if (!refreshTokens.includes(refreshToken)) {
    return res.status(403).json("refresh token is not valid");
  }
  jwt.verify(refreshToken, "myRefreshSecretKey", (err, user) => {
    err && console.log(err);

    refreshTokens = refreshTokens.filter((token) => token !== refreshToken);

    const newAccessToken = generateAccessToken(user);
    const newRefreshToken = generateAccessToken(user);

    refreshTokens.push(newRefreshToken);

    res.status(200).json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  });
});

function generateAccessToken(user) {
  const accessToken = jwt.sign(
    { id: user.id, isAdmin: user.isAdmin },
    "mySecretKey",
    { expiresIn: "15m" }
  );

  return accessToken;
}

function generateRefreshToken(user) {
  const refreshToken = jwt.sign(
    { id: user.id, isAdmin: user.isAdmin },
    "myRefreshSecretKey",
    {
      expiresIn: "15m",
    }
  );

  return refreshToken;
}

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => {
    return u.username === username && u.password === password;
  });
  if (user) {
    //generate an access token
    // const accessToken = jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "mySecretKey", { expiresIn: "15m" })

    const accessToken = generateAccessToken(user);

    // const refreshToken = jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "myRefreshSecretKey", { expiresIn: "15m" })

    const refreshToken = generateRefreshToken(user);

    refreshTokens.push(refreshToken);

    res.json({
      username: user.username,
      isAdmin: user.isAdmin,
      accessToken,
      refreshToken,
    });
  } else {
    res.status(400).json({ message: "wrong" });
  }
});

const verify = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, "mySecretKey", (err, user) => {
      if (err) {
        return res.status(403).json("token is not valid");
      }
      //store in the req to share it to the delete route
      req.user = user;

      next();
    });
  } else {
    res.status(401).json("you are not authenticated");
  }
};

app.post("/api/logout", verify, (req, res) => {
  const refreshToken = req.body.token;
  refreshTokens = refreshTokens.filter((token)=>token !== refreshToken);
  res.status(200).json("logged out successfully");
});

app.delete("/api/users/:userId", verify, (req, res) => {
  if (req.user.id === req.params.userId || req.user.isAdmin) {
    res.status(200).json("user has been deleted");
  } else {
    res.status(403).json("user not allowed");
  }
});

app.listen(3000, () => {
  console.log("server started");
});
