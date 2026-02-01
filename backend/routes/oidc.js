import crypto from "crypto";
import express from "express";
import oidc from "openid-client";
import internalToken from "../internal/token";
import error from "../lib/error";
import jwtdecode from "../lib/express/jwt-decode";
import { oidc as logger } from "../logger";
import settingModel from "../models/setting";

const router = express.Router({
	caseSensitive: true,
	strict: true,
	mergeParams: true,
});

router
	.route("/")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())

	/**
	 * GET /api/oidc
	 *
	 * OAuth Authorization Code flow initialisation
	 */
	.get(jwtdecode(), async (req, res) => {
		logger.info("Initializing OAuth flow");
		settingModel
			.query()
			.where({ id: "oidc-config" })
			.first()
			.then((row) => getInitParams(req, row))
			.then((params) => redirectToAuthorizationURL(res, params))
			.catch((err) => redirectWithError(res, err));
	});

router
	.route("/callback")
	.options((_, res) => {
		res.sendStatus(204);
	})
	.all(jwtdecode())

	/**
	 * GET /api/oidc/callback
	 *
	 * Oauth Authorization Code flow callback
	 */
	.get(jwtdecode(), async (req, res) => {
		logger.info("Processing callback");
		try {
			const settings = await settingModel.query().where({ id: "oidc-config" }).first();
			const token = validateCallback(req, settings);
			redirectWithJwtToken(res, token);
		} catch (err) {
			redirectWithError(res, err);
		}
	});

/**
 * Executes discovery and returns the configured `openid-client` client
 *
 * @param {Setting} row
 * */
const getClient = async (row) => {
	let issuer;
	try {
		issuer = await oidc.Issuer.discover(row.meta.issuerURL);
	} catch (err) {
		throw new error.AuthError(`Discovery failed for the specified URL with message: ${err.message}`);
	}

	return new issuer.Client({
		client_id: row.meta.clientID,
		client_secret: row.meta.clientSecret,
		redirect_uris: [row.meta.redirectURL],
		response_types: ["code"],
	});
};

/**
 * Generates state, nonce and authorization url.
 *
 * @param {Request} req
 * @param {Setting} row
 * @return { {String}, {String}, {String} } state, nonce and url
 * */
const getInitParams = async (req, row) => {
	const client = await getClient(row),
		state = crypto.randomUUID(),
		nonce = crypto.randomUUID(),
		url = client.authorizationUrl({
			scope: "openid email profile",
			resource: `${req.protocol}://${req.get("host")}${req.originalUrl}`,
			state,
			nonce,
		});

	return { state, nonce, url };
};

/**
 * Parses state and nonce from cookie during the callback phase.
 *
 * @param {Request} req
 * @return { {String}, {String} } state and nonce
 * */
const parseStateFromCookie = (req) => {
	let state, nonce;
	const cookies = req.headers.cookie.split(";");
	for (const cookie of cookies) {
		if (cookie.split("=")[0].trim() === "npm_oidc") {
			const raw = cookie.split("=")[1],
				val = raw.split("--");
			state = val[0].trim();
			nonce = val[1].trim();
			break;
		}
	}

	return { state, nonce };
};

/**
 * Executes validation of callback parameters.
 *
 * @param {Request} req
 * @param {Setting} settings
 * @return {Promise} a promise resolving to a jwt token
 * */
const validateCallback = async (req, settings) => {
	const client = await getClient(settings);
	const { state, nonce } = parseStateFromCookie(req);

	const params = client.callbackParams(req);
	const tokenSet = await client.callback(settings.meta.redirectURL, params, { state, nonce });
	const claims = tokenSet.claims();

	if (!claims.email) {
		throw new error.AuthError("The Identity Provider didn't send the 'email' claim");
	}
	logger.info("Successful authentication for email " + claims.email);

	return internalToken.getTokenFromOAuthClaim({ identity: claims.email });
};

const redirectToAuthorizationURL = (res, params) => {
	logger.info("Authorization URL: " + params.url);
	res.cookie("npm_oidc", params.state + "--" + params.nonce);
	res.redirect(params.url);
};

const redirectWithJwtToken = (res, token) => {
	res.cookie("npm_oidc", token.token + "---" + token.expires);
	res.redirect("/login");
};

const redirectWithError = (res, error) => {
	logger.error("Callback error: " + error.message);
	res.cookie("npm_oidc_error", error.message);
	res.redirect("/login");
};

export default router;
