export const cookies = {
  getOptions: () => ({ 
    sameSite: 'strict',
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: 15 * 60 * 1000,
  }),

  set: (res, name, value, options = {}) => {
    res.cookie(name, value, { ...cookies.getOptions(), ...options });
  },

  clear: (res, name, options = {}) => {
    res.clearCookie(name, { ...cookies.getOptions(), ...options });
  },

  get: (req, name) => {
    return req.cookies[name];
  }
};