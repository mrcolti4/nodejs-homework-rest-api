import { Schema, model } from "mongoose";
import Joi from "joi";

const contactSchema = new Schema(
  {
    name: {
      type: String,
      required: [true, "Set name for contact"],
    },
    email: {
      type: String,
    },
    phone: {
      type: String,
    },
    favorite: {
      type: Boolean,
      default: false,
    },
  },
  { timestamps: true }
);

const phonePattern =
  /\+?\d{1,4}?[-.\s]?\(?\d{1,3}?\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}/;
const emailPattern =
  /^[-!#$%&'*+/0-9=?A-Z^_a-z{|}~](\.?[-!#$%&'*+/0-9=?A-Z^_a-z{|}~])*@[a-zA-Z](-?[a-zA-Z0-9])*(\.[a-zA-Z](-?[a-zA-Z0-9])*)+$/;

export const contactAddSchema = Joi.object({
  name: Joi.string().trim().min(2).max(15).messages({
    "string.base": `"name" should be a type of text`,
    "string.empty": `"name" cannot be an empty string`,
    "string.min": `"name" should have minimum length of 2`,
    "any.required": `"name" is a required field`,
  }),
  phone: Joi.string()
    .trim()
    .min(5)
    .max(10)
    .pattern(new RegExp(phonePattern))
    .messages({
      "string.base": `"phone" should be a type of text`,
      "string.empty": `"phone" cannot be an empty string`,
      "string.pattern.base": `"phone" should have at least 5 numbers and it can be divided by "-"`,
    }),
  email: Joi.string().pattern(new RegExp(emailPattern)),
});

export const contactFavoriteSchema = Joi.object({
  favorite: Joi.boolean()
    .required()
    .messages({ "any.required": `missing field favorite` }),
});

const handleSaveError = (error, data, next) => {
  error.status = 400;
  next();
};

const runValidatorsAtUpdate = function (next) {
  this.options.runValidators = true;
  this.options.new = true;
  next();
};

contactSchema.post("save", handleSaveError);
contactSchema.pre("findOneAndUpdate", runValidatorsAtUpdate);
contactSchema.post("findOneAndUpdate", handleSaveError);

export const Contact = model("contacts", contactSchema);
