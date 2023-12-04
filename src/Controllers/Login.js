import db from "../Config/database.js";
import { v4 as uuid } from 'uuid';
import bcrypt from 'bcrypt';
import userSchema from "../Model/LoginSchema.js";

export async function SignIn(req, res) {
  try {
    const { email, password } = req.body;
    const user = await db.collection('users').findOne({ email });

    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(400).send("Usuário e/ou senha incorretos!");
    }

    const token = uuid();
    await db.collection('sessions').insertOne({ userID: user._id, token });

    res.status(200).send({ name: user.name, userID: user._id, token });
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
}

export async function SignUp(req, res) {
  try {
    const { name, email, password, confirmPassword } = req.body;

    const { error } = userSchema.validate(
      { name, email, password, confirmPassword },
      { abortEarly: false }
    );

    if (error) {
      const errorMessages = error.details.map(e => e.message);
      console.log(errorMessages);
      return res.status(422).send(errorMessages);
    }

    const passwordHashed = bcrypt.hashSync(password, 10);

    await db.collection("users").insertOne({
      name,
      email,
      password: passwordHashed
    });

    res.status(201).send("Usuário cadastrado com sucesso!");
  } catch (error) {
    console.error(error);
    res.sendStatus(500);
  }
}
