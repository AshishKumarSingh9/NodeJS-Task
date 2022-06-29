module.exports = fn => {
  return (req, res, next) => {
    //returns a promise, so chaining a catch method.
    fn(req, res, next).catch(err => next(err)); // instead of 'err => next(err)' we can also just write 'next'
  };
};
