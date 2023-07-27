// JS implementation of a Client-side Encrypted Mail Transfer Protocol (CEMTP) user client.
// Copyright (C) 2023 Web Scale Software Ltd. Licensed under the MIT license.
// Written By: Astrid Gealer <astrid@webscalesoftware.ltd>

export enum ErrorCode {
    // ErrNotSpecCompliant is thrown when the response is not spec compliant.
    ErrNotSpecCompliant = "ERR_NOT_SPEC_COMPLIANT",

    // ErrAuthenticationFailure is thrown when the authentication fails.
    ErrAuthenticationFailure = "ERR_AUTHENTICATION_FAILURE",

    // ErrAdditionalAuth is thrown when additional authentication is required.
    ErrAdditionalAuth = "ERR_ADDITIONAL_AUTH",

    // ErrNotFound is thrown when the resource is not found.
    ErrNotFound = "ERR_NOT_FOUND",

    // ErrMailRejected is thrown when the mail is rejected.
    ErrMailRejected = "ERR_MAIL_REJECTED",
}

// Get an array of all the enums.
const ErrorCodesArray = Object.values(ErrorCode);

// This is a error that is thrown for all specification related errors.
export class SpecificationError extends Error {
    public code: ErrorCode;
    public statusCode: number;
    public body: string;
    public description: string;
    public token_flow_url?: string;
    public token_fetch_url?: string;

    constructor(opts: {
        code: ErrorCode,
        statusCode: number,
        body: string,
        description: string,
        token_flow_url?: string,
        token_fetch_url?: string,
    }) {
        super(opts.description);

        this.code = opts.code;
        this.statusCode = opts.statusCode;
        this.body = opts.body;
        this.description = opts.description;
        this.token_flow_url = opts.token_flow_url;
        this.token_fetch_url = opts.token_fetch_url;
    }
}

// Handle errors from the fetch result.
export const handleError = async (response: Response, passwordAuth: boolean) => {
    // Check X-Cemtp-Version is set to 1.0.
    if (response.headers.get("X-Cemtp-Version") !== "1.0") {
        throw new SpecificationError({
            code: ErrorCode.ErrNotSpecCompliant,
            statusCode: response.status,
            body: await response.text(),
            description: "The X-Cemtp-Version header is not set to 1.0.",
        });
    }

    // Get the object.
    const body = await response.text();
    let object: any;
    try {
        object = JSON.parse(body);
    } catch (_) {
        throw new SpecificationError({
            code: ErrorCode.ErrNotSpecCompliant,
            statusCode: response.status,
            body,
            description: "The response is not valid JSON.",
        });
    }

    // Make sure the object is an object.
    if (typeof object !== "object") {
        throw new SpecificationError({
            code: ErrorCode.ErrNotSpecCompliant,
            statusCode: response.status,
            body,
            description: "The response is not an object.",
        });
    }

    // Check the error code is within the specification.
    if (!ErrorCodesArray.includes(object.error_code)) {
        throw new SpecificationError({
            code: ErrorCode.ErrNotSpecCompliant,
            statusCode: response.status,
            body,
            description: "The error code is not within the specification.",
        });
    }

    // If the error code is ErrAdditionalAuth and password auth is false, throw an error.
    if (object.error_code === ErrorCode.ErrAdditionalAuth && !passwordAuth) {
        throw new SpecificationError({
            code: ErrorCode.ErrNotSpecCompliant,
            statusCode: response.status,
            body,
            description: "The error code is ErrAdditionalAuth but password auth is false.",
        });
    }

    // Get the error code as a enum.
    const code = object.error_code as ErrorCode;

    // Get the description.
    const description = object.description as string;
    if (typeof description !== "string") {
        throw new SpecificationError({
            code: ErrorCode.ErrNotSpecCompliant,
            statusCode: response.status,
            body,
            description: "The description is not a string.",
        });
    }

    // Get the flow information if appropriate.
    let token_flow_url: string | undefined;
    let token_fetch_url: string | undefined;
    if (code === ErrorCode.ErrAdditionalAuth) {
        token_flow_url = object.token_flow_url as string;
        token_fetch_url = object.token_fetch_url as string;
        if (typeof token_flow_url !== "string") {
            throw new SpecificationError({
                code: ErrorCode.ErrNotSpecCompliant,
                statusCode: response.status,
                body,
                description: "The token flow URL is not a string.",
            });
        }
        if (typeof token_fetch_url !== "string") {
            throw new SpecificationError({
                code: ErrorCode.ErrNotSpecCompliant,
                statusCode: response.status,
                body,
                description: "The token fetch URL is not a string.",
            });
        }
    }

    // Throw the correct error.
    throw new SpecificationError({
        code, statusCode: response.status, body, description,
        token_flow_url, token_fetch_url,
    });
};

// This error is thrown then the response is not spec compliant.
export class ResponseNonSpecCompliant extends Error {}

// This error is thrown when it is unable to prompt.
export class UnableToPrompt extends Error {
    constructor() {
        super("Unable to create a prompt.");
    }
}

// This error is thrown when the prompt response is not valid.
export class PromptResponseError extends Error {}
