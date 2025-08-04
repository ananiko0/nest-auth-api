import * as Joi from 'joi';

export const validationSchema = Joi.object({
  PORT: Joi.number().default(3000),

  DB_HOST: Joi.string().required().label('Database host'),
  DB_PORT: Joi.number().default(5432).label('Database port'),
  DB_USER: Joi.string().required().label('Database user'),
  DB_PASS: Joi.string().required().label('Database password'),
  DB_NAME: Joi.string().required().label('Database name'),

  JWT_SECRET: Joi.string().min(12).required().label('JWT Secret').messages({
    'string.min': 'JWT_SECRET must be at least 12 characters',
    'any.required': 'JWT_SECRET is required',
  }),
});
