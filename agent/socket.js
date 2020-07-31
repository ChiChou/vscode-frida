rpc.exports.find = function() {
  return Socket.listen().then(listener => {
    try {
      return listener.port;
    } finally {
      listener.close();
    }
  });
}
