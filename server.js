const express = require('express');
const app = express();

// listen for requests on port 3000
app.listen(3001);

/* app.get() is used to respond to Get requests, and it takes two arguments: 
1- arg1: represents what path/url you want to listen to (e.g., '/' listens to index path)
2- arg2: represents a function that takes in request and response objects */

app.get('/', (req, res) => {
    // res.send can be used to send text and HTML snippets
    //res.send('</h1>First HTML response message! </h1>');

    /* res.sendFile() is a method that can be used to send files as its name indicates
    However, it takes the absolute not the relative path to the file. Therefore, you need to specify what is the root directory.
    To avoid this confusion, you can use  "__dirname"*/
    res.sendFile('./views/index.html', { root: __dirname });
    console.log(__dirname);
});

// do not write in the URL address bar the extension of the page. For example, writing (http://localhost:3000/posts.html) will direct you to the 404 page
app.get('/posts', (req, res) => {
    res.sendFile('./views/posts.html', { root: __dirname });
});



// We will discuss this method next week, when we speak about Middlewares
app.use((req, res) => {
    res.status(404).sendFile('./views/404.html', { root: __dirname });
});
