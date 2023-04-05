import type { Context, Service, ServiceSchema } from "moleculer";
import type { DbAdapter, DbServiceSettings, MoleculerDbMethods } from "moleculer-db";
import type MongoDbAdapter from "moleculer-db-adapter-mongo";
import type { DbServiceMethods } from "../mixins/db.mixin";
import DbMixin from "../mixins/db.mixin";
const argon2 = require("argon2");
const jwt = require("jsonwebtoken");

export interface UserEntity {
	_id: string;
	username: string;
	password: string;
	email: string;
	createdAt: Date;
	updatedAt: Date;
}

export interface Route {
	path: string;
	authorization: boolean;
	authentication: boolean;
}

export interface Routes {
	routes: Route[];
}

export type ActionCreateParams = Partial<UserEntity>;

interface AuthSettings extends DbServiceSettings, Routes {
	indexes?: Record<string, number>[];
}

interface AuthThis extends Service<AuthSettings>, MoleculerDbMethods {
	adapter: DbAdapter | MongoDbAdapter;
}

const AuthService: ServiceSchema<AuthSettings> & { methods: DbServiceMethods } = {
	name: "auth",
	// version: 1

	/**
	 * Mixins
	 */
	mixins: [DbMixin("auth")],

	/**
	 * Settings
	 */
	settings: {
		// Available fields in the responses
		fields: [
			"_id",
			"username",
			"-password", // adding "-" will exclude the field from the response
			"email",
		],
		// Validator for the `create` & `insert` actions.
		entityValidator: {
			username: "string|min:3",
			password: "string|min:6",
			email: "string|email",
		},
		routes: [
			{
				path: "/login",
				authorization: false,
				authentication: false,
			},
			{
				path: "/register",
				authorization: false,
				authentication: false,
			},
			/**
			 * Logout action needs authorization
			 */
			{
				path: "/logout",
				authorization: true,
				authentication: false,
			},
		],
		indexes: [{ name: 2 }],
	},

	/**
	 * Action Hooks
	 */
	hooks: {
		before: {
			/**
			 * Register a before hook for the `create` action.
			 * It sets a default value for the quantity field.
			 */
			create(ctx: Context<ActionCreateParams>) {
				ctx.params.createdAt = new Date();
				ctx.params.updatedAt = new Date();
			},
		},
	},

	/**
	 * Actions
	 */

	actions: {
		// make create callable only from services
		create: {
			visibility: "protected",
		},
		// make find callable only from services
		find: {
			visibility: "protected",
		},
		remove: {
			visibility: "protected",
		},
		update: {
			visibility: "protected",
		},
		list: {
			visibility: "protected",
		},
		login: {
			// rest setting on every path is very important to implement correctly the authentication based on api.service.ts
			rest: {
				method: "POST",
				path: "/login",
			},
			params: {
				username: "string",
				password: "string",
			},
			async handler(ctx: Context<{ username: string; password: string }>) {
				const { username, password } = ctx.params;
				const user: { password: string; email: string; _id: string } =
					await this.adapter.findOne({
						username: username,
					});
				console.log("user", user);
				if (user) {
					const isPasswordValid = await argon2.verify(user.password, password);
					if (isPasswordValid) {
						const token = jwt.sign(
							{ email: user.email, id: user._id },
							process.env.JWT_SECRET,
							{
								expiresIn: "7d",
							},
						);
						return {
							message: "Login successful",
							token,
						};
					} else {
						return {
							message: "Invalid password",
						};
					}
				} else {
					return {
						message: "User not found",
					};
				}
			},
		},

		register: {
			rest: {
				method: "POST",
				path: "/register",
			},
			params: {
				username: "string",
				password: "string",
				email: "string",
			},
			async handler(ctx: Context<{ username: string; password: string; email: string }>) {
				const { username, password, email } = ctx.params;
				const user: { password: string; email: string; _id: string } =
					await this.adapter.findOne({
						username: username,
					});
				if (user) {
					return {
						message: "User already exists",
					};
				} else {
					const hashedPassword = await argon2.hash(password);
					const newUser = await ctx.call("auth.create", {
						username,
						password: hashedPassword,
						email,
					});
					return {
						message: "User created successfully",
						user: newUser,
					};
				}
			},
		},

		logout: {
			rest: {
				method: "POST",
				path: "/logout",
			},
			async handler(ctx: Context) {
				const token = this.getToken(ctx);
				if (token) {
					const tokenKey = `bl_${token}`;
					await this.broker.cacher?.set(tokenKey, token);
					return "Logout successful!";
				}
				return "Token not found!";
			},
		},
	},
	methods: {
		getToken(ctx) {
			const token =
				ctx.options.parentCtx.params.req.headers.authorization &&
				ctx.options.parentCtx.params.req.headers.authorization.replace("Bearer ", "");
			return token;
		},
	},

	/**
	 * Fired after database connection establishing.
	 */
	async afterConnected(this: AuthThis) {
		if ("collection" in this.adapter) {
			if (this.settings.indexes) {
				await Promise.all(
					this.settings.indexes.map((index) =>
						(<MongoDbAdapter>this.adapter).collection.createIndex(index),
					),
				);
			}
		}
	},
};

export default AuthService;
