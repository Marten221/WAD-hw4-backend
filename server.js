const express = require('express');
const pool = require('./database');
const cors = require('cors');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');

const port = process.env.PORT || 3000;

const app = express();

app.use(cors({ origin: 'http://localhost:8080', credentials: true }));
app.use(express.json());
app.use(cookieParser());

const secret = "13887c9e1458c7555eb5813e24967f9f783da0cf5373e5deaf9a94020560bc91a9a8244dfade29da02a3fb7a429e066597d815db16990b1eb9d5dea34f4dcc97bd53fd010d5797de7e39864174cff25571b5b7a4891098456bdf287aa36857a46a2bb02f80cdd3c4d85335ab030344762ae33d08d929701717517d26c12089b1f116029181d616d5b26a05ca619e53301f473bfdd5a91239ff58bf8cce2b2e5ccb670f76b5883fa53750e25796526931e92f2dd7482b87c8456a1818076d31bfbee99510f9576906c728ff382b1b3cf63d5a4194ef14eef6d005d71691f6657cf0c95443cbc5c5632d000ead4b85e4ffc2fb0896bb2c2d7579654970ed9a8728";
const maxAge = 60 * 60;

const generateJWT = (id) => {
    return jwt.sign({ id }, secret, { expiresIn: maxAge });
};

// listen for requests on port 3000
app.listen(port, () => {
    console.log("Server is listening to port: " + port)
});



signUpQuery = "INSERT INTO users(email,password) values ($1, $2) RETURNING*"
app.post('/auth/signup', async (req, res) => {
    try {
        console.log("Signup request arrived!")
        const { email, password } = req.body;

        const salt = await bcrypt.genSalt();
        const bcryptPassword = await bcrypt.hash(password, salt);
        const authUser = await pool.query(signUpQuery, [email, bcryptPassword]);

        console.log(authUser.rows[0]);
        const token = await generateJWT(authUser.rows[0].id);
        res
            .status(201)
            .cookie('jwt', token, { maxAge: 6000000, httpOnly: true })
            .json({ user_id: authUser.rows[0].id })
            .send;
    } catch (error) {
        res.status(401).json({ error: error.message })
    }
})

app.get('/auth/authenticate', async (req, res) => {
    console.log("Auth req arrived!")
    const token = req.cookies.jwt;
    console.log("token: ", token);

    let authenticated = false;
    try {
        if (token) {
            await jwt.verify(token, secret, (err) => {
                if (err) {
                    console.log('Token not verified: ', err.message)
                    res.send({ "authenticated": authenticated })
                } else {
                    console.log("User successfully authenticated")
                    authenticated = true;
                    res.send({ "authenticated": authenticated });
                }
            })
        } else {
            console.log("Token does not exist");
            res.send({ "authenticated": authenticated })
        }
    } catch (err) {
        console.log(err.message);
        res.status(400).send(err.message)
    }
});

getCredentialsQuery = "SELECT * FROM users WHERE email = $1"
app.post('/auth/login', async (req, res) => {
    try {
        console.log("Login request arrived!")
        const { email, password } = req.body

        const user = await pool.query(getCredentialsQuery, [email]);
        if (user.rows.length === 0) return res.status(401).json({ error: "User is not registered" })

        const validPassword = await bcrypt.compare(password, user.rows[0].password);
        if (!validPassword) return res.status(401).json({ error: "Incorrect password" });

        const token = await generateJWT(user.rows[0].id);
        res 
            .status(201)
            .cookie('jwt', token, { maxAge: 6000000, httpOnly: true})
            .json({ user_id: user.rows[0]. id })
            .send;
    } catch (error) {
        res.status(401).json({ error: error.message });
    }
});

app.get('/auth/logout', (req, res) => {
    console.log("Logout req arrived!")
    res.status(202).clearCookie("jwt").json({"Msg": "cookie cleared"}).send
});

app.get('/posts', async (req, res) => {
    try {
        const posts = await pool.query('SELECT * FROM posts ORDER BY id DESC');
        res.status(200).json(posts.rows);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/posts', async (req, res) => {
    try {
        const { content } = req.body;

        const newPost = await pool.query(
            'INSERT INTO posts (content) VALUES ($1) RETURNING *',
            [content]
        );
        res.status(201).json(newPost.rows[0]);
    } catch (error) {
        console.error('Error adding post:', error.message);
        res.status(500).json({ error: 'Failed to add post' });
    }
});

app.get('/posts/:id', async (req, res) => {
    const postId = req.params.id;

    try {
        const result = await pool.query('SELECT * FROM posts WHERE id = $1', [postId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Post not found' });
        }

        res.status(200).json(result.rows[0]);
    } catch (error) {
        console.error('Error fetching post:', error.message);
        res.status(500).json({ error: 'Failed to fetch post' });
    }
});


app.put('/posts/:id', async (req, res) => {
    const { id } = req.params;
    const { content } = req.body;

    try {
        const result = await pool.query(
            'UPDATE posts SET content = $1 WHERE id = $2 RETURNING *',
            [content, id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "Post not found." });
        }

        res.status(200).json({ message: "Post updated successfully.", post: result.rows[0] });
    } catch (error) {
        console.error('Error updating post:', error.message);
        res.status(500).json({ error: 'Failed to update post' });
    }
});

app.delete('/posts/:id', async (req, res) => {
    const postId = req.params.id;

    try {
        const result = await pool.query('DELETE FROM posts WHERE id = $1 RETURNING *', [postId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "Post not found." });
        }

        res.status(200).json({ message: "Post deleted successfully.", post: result.rows[0] });
    } catch (error) {
        console.error('Error deleting post:', error.message);
        res.status(500).json({ error: 'Failed to delete post.' });
    }
});