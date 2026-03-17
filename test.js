const express = require('express');
const app = express();

app.get('/', (req, res) => {
    res.send('🔥 ROOT WORKING!');
});

app.listen(5000, () => {
    console.log('Server running on 5000');
});