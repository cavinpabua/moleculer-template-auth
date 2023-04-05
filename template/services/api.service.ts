import type { ActionSchema, Context, RestSchema, ServiceSchema } from "moleculer";
import type { ApiSettingsSchema, GatewayResponse, IncomingRequest, Route } from "moleculer-web";
import ApiGateway from "moleculer-web";

const jwt = require("jsonwebtoken");

interface Meta {
	userAgent?: string | null | undefined;
	user?: object | null | undefined;
}

const ApiService: ServiceSchema<ApiSettingsSchema> = {
	name: "api",
	mixins: [ApiGateway],

	// More info about settings: https://moleculer.services/docs/0.14/moleculer-web.html
	settings: {
		// Exposed port
		port: process.env.PORT != null ? Number(process.env.PORT) : 3000,

		// Exposed IP
		ip: "0.0.0.0",

		// Global Express middlewares. More info: https://moleculer.services/docs/0.14/moleculer-web.html#Middlewares
		use: [],

		routes: [
			{
				path: "/api",

				whitelist: ["**"],

				// Route-level Express middlewares. More info: https://moleculer.services/docs/0.14/moleculer-web.html#Middlewares
				use: [],

				// Enable/disable parameter merging method. More info: https://moleculer.services/docs/0.14/moleculer-web.html#Disable-merging
				mergeParams: true,

				// Enable authentication. Implement the logic into `authenticate` method. More info: https://moleculer.services/docs/0.14/moleculer-web.html#Authentication
				authentication: false,

				// Enable authorization. Implement the logic into `authorize` method. More info: https://moleculer.services/docs/0.14/moleculer-web.html#Authorization
				authorization: false,

				// The auto-alias feature allows you to declare your route alias directly in your services.
				// The gateway will dynamically build the full routes from service schema.
				autoAliases: true,

				aliases: {},

				/**
				 * Before call hook. You can check the request.
				 *
				onBeforeCall(
					ctx: Context<unknown, Meta>,
					route: Route,
					req: IncomingRequest,
					res: GatewayResponse,
				): void {
					// Set request headers to context meta
					ctx.meta.userAgent = req.headers["user-agent"];
				}, */

				/**
				 * After call hook. You can modify the data.
				 *
				onAfterCall(
					ctx: Context,
					route: Route,
					req: IncomingRequest,
					res: GatewayResponse,
					data: unknown,
				): unknown {
					// Async function which return with Promise
					// return this.doSomething(ctx, res, data);
					return data;
				}, */

				// Calling options. More info: https://moleculer.services/docs/0.14/moleculer-web.html#Calling-options
				callingOptions: {},

				bodyParsers: {
					json: {
						strict: false,
						limit: "1MB",
					},
					urlencoded: {
						extended: true,
						limit: "1MB",
					},
				},

				// Mapping policy setting. More info: https://moleculer.services/docs/0.14/moleculer-web.html#Mapping-policy
				mappingPolicy: "all", // Available values: "all", "restrict"

				// Enable/disable logging
				logging: true,
			},
		],

		// Do not log client side errors (does not log an error response when the error.code is 400<=X<500)
		log4XXResponses: false,
		// Logging the request parameters. Set to any log level to enable it. E.g. "info"
		logRequestParams: null,
		// Logging the response data. Set to any log level to enable it. E.g. "info"
		logResponseData: null,

		// Serve assets from "public" folder. More info: https://moleculer.services/docs/0.14/moleculer-web.html#Serve-static-files
		assets: {
			folder: "public",

			// Options to `server-static` module
			options: {},
		},
	},

	methods: {
		/**
		 * Authenticate the request. It check the `Authorization` token value in the request header.
		 * Check the token value & resolve the user by the token.
		 * The resolved user will be available in `ctx.meta.user`
		 *
		 * PLEASE NOTE, IT'S JUST AN EXAMPLE IMPLEMENTATION. DO NOT USE IN PRODUCTION!
		 */
		async authenticate(
			ctx: Context & { meta: Meta },
			route: Route,
			req: IncomingRequest,
		): Promise<Record<string, unknown> | null> {
			// Read the token from header
			const self = this;
			const auth = req.headers.authorization;
			const rest = req.$action.rest;
			if (auth && auth.startsWith("Bearer")) {
				const token = auth.slice(7);

				// First check for multiple routes under settings
				const routeSettingFound =
					rest &&
					req.$action.service?.settings.routes &&
					req.$action.service.settings.routes.find(
						(o: { path: any }) => o.path === (rest as RestSchema).path,
					);
				if (routeSettingFound) {
					if (routeSettingFound.authentication && token) {
						// Check if token is in deny list
						const inDenyList = await self.broker.cacher?.get(`bl_${token}`);
						if (inDenyList) {
							throw new ApiGateway.Errors.UnAuthorizedError(
								ApiGateway.Errors.ERR_INVALID_TOKEN,
								null,
							);
						}

						const verified = jwt.verify(token, process.env.JWT_SECRET);
						if (verified) {
							ctx.meta.user = {
								email: verified.email,
								id: verified.id,
								token: token,
								exp: verified.exp,
								iat: verified.iat,
							};

							return {
								email: verified.email,
								id: verified.id,
								token: token,
								exp: verified.exp,
								iat: verified.iat,
							};
						} else {
							// Invalid token
							throw new ApiGateway.Errors.UnAuthorizedError(
								ApiGateway.Errors.ERR_INVALID_TOKEN,
								null,
							);
						}
					}
					return null;
				} else {
					// Check if whole service is private
					const isServicePrivate =
						req.$action.service?.settings.routes &&
						req.$action.service.settings.routes[0].authentication &&
						token;

					if (isServicePrivate) {
						const inDenyList = await self.broker.cacher?.get(`bl_${token}`);
						if (inDenyList) {
							throw new ApiGateway.Errors.UnAuthorizedError(
								ApiGateway.Errors.ERR_INVALID_TOKEN,
								null,
							);
						}
						const verified = jwt.verify(token, process.env.JWT_SECRET);
						// Check the token. Tip: call a service which verify the token. E.g. `accounts.resolveToken`
						if (verified) {
							// Returns the resolved user. It will be set to the `ctx.meta.user`
							ctx.meta.user = {
								email: verified.email,
								id: verified.id,
								token: token,
								exp: verified.exp,
								iat: verified.iat,
							};
							return {
								email: verified.email,
								id: verified.id,
								token: token,
								exp: verified.exp,
								iat: verified.iat,
							};
						} else {
							// Invalid token
							throw new ApiGateway.Errors.UnAuthorizedError(
								ApiGateway.Errors.ERR_INVALID_TOKEN,
								null,
							);
						}
					} else {
						return null;
					}
				}
			} else {
				return null;
			}
		},

		/**
		 * Authorize the request. Check that the authenticated user has right to access the resource.
		 *
		 * PLEASE NOTE, IT'S JUST AN EXAMPLE IMPLEMENTATION. DO NOT USE IN PRODUCTION!
		 */
		authorize(ctx: Context<null, Meta>, route: Route, req: IncomingRequest) {
			// Get the authenticated user.
			// user object contains what is set in `ctx.meta.user` in `authenticate` method.
			const { user } = ctx.meta;

			// You can implement any authorization logic here.
			// It check the `auth` property in action schema.
			if (req.$action.auth === "required" && !user) {
				throw new ApiGateway.Errors.UnAuthorizedError("NO_RIGHTS", null);
			}
		},
	},
};

export default ApiService;
