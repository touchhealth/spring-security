/*
 * Copyright 2002-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.saml2.provider.service.authentication.logout;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;

import net.shibboleth.utilities.java.support.xml.ParserPool;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.impl.LogoutResponseUnmarshaller;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.provider.service.authentication.logout.OpenSamlVerificationUtils.VerifierPartial;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;

/**
 * A {@link Saml2LogoutResponseValidator} that authenticates a SAML 2.0 Logout Responses
 * received from a SAML 2.0 Asserting Party using OpenSAML.
 *
 * @author Josh Cummings
 * @since 5.6
 */
public class OpenSamlLogoutResponseValidator implements Saml2LogoutResponseValidator {

	static {
		OpenSamlInitializationService.initialize();
	}

	private final ParserPool parserPool;

	private final LogoutResponseUnmarshaller unmarshaller;

	/**
	 * Constructs an {@link OpenSamlLogoutResponseValidator}
	 */
	public OpenSamlLogoutResponseValidator() {
		XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		this.parserPool = registry.getParserPool();
		this.unmarshaller = (LogoutResponseUnmarshaller) XMLObjectProviderRegistrySupport.getUnmarshallerFactory()
			.getUnmarshaller(LogoutResponse.DEFAULT_ELEMENT_NAME);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Saml2LogoutValidatorResult validate(Saml2LogoutResponseValidatorParameters parameters) {
		Saml2LogoutResponse response = parameters.getLogoutResponse();
		Saml2LogoutRequest request = parameters.getLogoutRequest();
		RelyingPartyRegistration registration = parameters.getRelyingPartyRegistration();
		byte[] b = Saml2Utils.samlDecode(response.getSamlResponse());
		LogoutResponse logoutResponse = parse(inflateIfRequired(response, b));
		Collection<Saml2Error> errors = verifySignature(response, logoutResponse, registration);
		if (!errors.isEmpty()) {
			return Saml2LogoutValidatorResult.withErrors(errors.toArray(new Saml2Error[0])).build();
		}
		errors = validateRequest(logoutResponse, registration, request.getId());
		return errors.isEmpty() ? Saml2LogoutValidatorResult.success()
				: Saml2LogoutValidatorResult.withErrors(errors.toArray(new Saml2Error[0])).build();
	}

	private String inflateIfRequired(Saml2LogoutResponse response, byte[] b) {
		if (response.getBinding() == Saml2MessageBinding.REDIRECT) {
			return Saml2Utils.samlInflate(b);
		}
		return new String(b, StandardCharsets.UTF_8);
	}

	private LogoutResponse parse(String response) throws Saml2Exception {
		try {
			Document document = this.parserPool
				.parse(new ByteArrayInputStream(response.getBytes(StandardCharsets.UTF_8)));
			Element element = document.getDocumentElement();
			return (LogoutResponse) this.unmarshaller.unmarshall(element);
		}
		catch (Exception ex) {
			throw new Saml2Exception("Failed to deserialize LogoutResponse", ex);
		}
	}

	private Collection<Saml2Error> verifySignature(Saml2LogoutResponse response, LogoutResponse logoutResponse,
			RelyingPartyRegistration registration) {
		VerifierPartial partial = OpenSamlVerificationUtils.verifySignature(logoutResponse, registration);
		if (logoutResponse.isSigned()) {
			return partial.post(logoutResponse.getSignature());
		}
		else {
			return partial.redirect(response);
		}
	}

	private Collection<Saml2Error> validateRequest(LogoutResponse response, RelyingPartyRegistration registration,
			String logoutRequestId) {
		Collection<Saml2Error> errors = new ArrayList<>();
		errors.addAll(validateIssuer(response, registration));
		errors.addAll(validateDestination(response, registration));
		errors.addAll(validateStatus(response));
		errors.addAll(validateLogoutRequest(response, logoutRequestId));
		return errors;
	}

	private Collection<Saml2Error> validateIssuer(LogoutResponse response, RelyingPartyRegistration registration) {
		if (response.getIssuer() == null) {
			return Collections.singletonList(
					new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER, "Failed to find issuer in LogoutResponse"));
		}
		String issuer = response.getIssuer().getValue();
		if (!issuer.equals(registration.getAssertingPartyDetails().getEntityId())) {
			return Collections.singletonList(
					new Saml2Error(Saml2ErrorCodes.INVALID_ISSUER, "Failed to match issuer to configured issuer"));
		}
		return Collections.emptyList();
	}

	private Collection<Saml2Error> validateDestination(LogoutResponse response, RelyingPartyRegistration registration) {
		if (response.getDestination() == null) {
			return Collections.singletonList(new Saml2Error(Saml2ErrorCodes.INVALID_DESTINATION,
					"Failed to find destination in LogoutResponse"));
		}
		String destination = response.getDestination();
		if (!destination.equals(registration.getSingleLogoutServiceResponseLocation())) {
			return Collections.singletonList(new Saml2Error(Saml2ErrorCodes.INVALID_DESTINATION,
					"Failed to match destination to configured destination"));
		}
		return Collections.emptyList();
	}

	private Collection<Saml2Error> validateStatus(LogoutResponse response) {
		if (response.getStatus() == null) {
			return Collections.emptyList();
		}
		if (response.getStatus().getStatusCode() == null) {
			return Collections.emptyList();
		}
		if (StatusCode.SUCCESS.equals(response.getStatus().getStatusCode().getValue())) {
			return Collections.emptyList();
		}
		if (StatusCode.PARTIAL_LOGOUT.equals(response.getStatus().getStatusCode().getValue())) {
			return Collections.emptyList();
		}
		return Collections
			.singletonList(new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE, "Response indicated logout failed"));
	}

	private Collection<Saml2Error> validateLogoutRequest(LogoutResponse response, String id) {
		if (response.getInResponseTo() == null) {
			return Collections.emptyList();
		}
		if (response.getInResponseTo().equals(id)) {
			return Collections.emptyList();
		}
		return Collections.singletonList(new Saml2Error(Saml2ErrorCodes.INVALID_RESPONSE,
				"LogoutResponse InResponseTo doesn't match ID of associated LogoutRequest"));
	}

}
