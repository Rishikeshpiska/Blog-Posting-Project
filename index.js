import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

let posts = [];
let user_id=0;

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    user_id=0;
    res.redirect("/");
  });
});

app.get("/posts", async (req, res) => {
  console.log('login');
  if (req.isAuthenticated()) {
    const user_id_result= await db.query("SELECT id FROM users WHERE email=$1",[req.user.email]);
    user_id=user_id_result.rows[0].id
    const result = await db.query("SELECT blogposts.* FROM blogposts INNER JOIN users ON blogposts.user_id = users.id WHERE users.email = $1 ORDER BY blogposts.dt", [req.user.email]);
    posts=result.rows;
    res.render('index.ejs', { posts: posts });
  } else {
    res.redirect("/login");
  }
});


app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/posts",
  passport.authenticate("google", {
    successRedirect: "/posts",
    failureRedirect: "/login",
  })
);

app.post('/login', 
  passport.authenticate('local', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/posts');
  });

app.post("/register", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      req.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            res.redirect("/");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

passport.use("local", new Strategy({
  usernameField: 'email'
}, async (email, password, cb) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;
      bcrypt.compare(password, storedHashedPassword, (err, valid) => {
        if (err) {
          console.error("Error comparing passwords:", err);
          return cb(err);
        }
        if (valid) {
          return cb(null, user); 
        } else {
          return cb(null, false);
        }
      });
    } else {
      return cb(null, false);
    }
  } catch (err) {
    console.error("Error during authentication:", err);
    return cb(err);
  }
}));


passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/posts",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);
passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.get("/new", (req, res) => {
  res.render("create.ejs", { heading: "New Post", submit: "Create Post" });
});

app.post("/create/posts", async (req, res) => {
  try {
  let title=req.body.title;
  let content=req.body.content;
  let author=req.body.author;
  let date=new Date();
  let result=await db.query("INSERT INTO blogposts (title,content,author,dt,user_id) VALUES ($1,$2,$3,$4,$5)",[title,content,author,date,user_id]);
  res.redirect("/posts");
  } catch (error) {
      console.log(`Error in create post request: ${error}`);
  res.status(500).json({ message: "Error creating post" });
  }
});

app.get("/edit/:id", async (req, res) => {
  try {
  const postId = parseInt(req.params.id);
  if (postId===-1) return res.status(404).json({ message: "Post not found" });
  let result=await db.query("SELECT * FROM blogposts WHERE id=$1",[postId]);
  let post=result.rows[0];
  res.render("edit.ejs", {heading: "Edit Post",submit: "Update Post",post: post});
  } catch (error) {
    res.status(500).json({ message: "Error fetching post" });
  }
});

app.post("/edit/posts/:id", async (req, res) => {
    const postId = parseInt(req.params.id);
    const title=req.body.title;
    const content=req.body.content;
    const author=req.body.author;
    const date=new Date();
    let result=await db.query("UPDATE blogposts SET title=$1, content=$2, author=$3, dt=$4 WHERE id=$5",[title,content,author,date,postId]);
    res.redirect("/posts");

});

app.get("/posts/delete/:id", async(req, res) => {
    const index = parseInt(req.params.id);
    if (index === -1) return res.status(404).json({ message: "Post not found" });
    await db.query("DELETE FROM blogposts WHERE id=$1",[index]);
    res.redirect("/posts");
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
