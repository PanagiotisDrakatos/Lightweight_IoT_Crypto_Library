// Retrieve
var MongoClient = require('mongodb').MongoClient;

// Connect to the db
MongoClient.connect("mongodb://localhost:27017/Keystores", function(err, db) {
    if (!err) {
        console.log("We are connected");
    }

    var collection = db.createCollection('Keystores', {
        strict: true
    }, function(err, collection) {});
    var ClientsDatas= [{
        'ClientPrivateID': 'random id'
    },{
        'ClientTimestamp': 'randomtimestamp'
    }, {
        'ClientPublickEY': 'random publickKey'
    }];

    collection.insert(ClientsDatas, {
        w: 1
    }, function(err, result) {});

    var stream = collection.find({
        hello: {
            $ne: 2
        }
    }).stream();
    stream.on("data", function(item) {});
    stream.on("end", function() {});

    collection.findOne({
        hello: 'ClientsDatas'
    }, function(err, item) {});

    db.close();
});
