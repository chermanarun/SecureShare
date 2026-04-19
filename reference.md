Authorization model

* OWASP Top 10 2025 and A01 Broken Access Control
    Broken access control remains the top application risk in OWASP 2025.  
* Google Zanzibar paper
    Foundational design for globally consistent relationship-based authorization.  
* OpenFGA docs
    Practical open source way to implement relationship-based authorization.  
* OPA docs
    Good fit when you want centralized policy decision-making separated from enforcement.  

Token security

* JWT Best Current Practices RFC 8725
    Good baseline for safe JWT handling and avoiding common mistakes.  
* Macaroons paper and implementations
    Best source for contextual, attenuated delegation tokens.  

Optional alternative engine

* SpiceDB docs
    Zanzibar-inspired alternative if you want a richer relationship engine later.  

Stack

* Frontend
    Next.js or React
* Backend
    FastAPI
* App database
    PostgreSQL
* Identity
    Local JWT issuer for dev first, later Auth0 or Keycloak
* PDP for relationship checks
    OpenFGA or SpiceDB
    I would start with OpenFGA because the docs and modeling path are straightforward for first implementation. OpenFGA is built for fine-grained authorization and relationship-based checks.  
* Optional policy layer for contextual rules
    OPA
    OPA is a clean fit when you want policy decision-making separate from enforcement, especially for non-relationship checks like tenant state, data sensitivity, device posture, or support-hours access.  
* PEP
    FastAPI middleware + route decorator + optional API gateway hook
* Delegation tokens
    Macaroon style tokens using pymacaroons or equivalent
    Macaroons support contextual caveats and attenuation, which is exactly why they fit delegated resource access better than plain JWT alone.  


Folder Structure
secureshare/
  apps/
    api/
      app/
        main.py
        middleware/
        routers/
        services/
        auth/
        authz/
        models/
        schemas/
        audit/
      tests/
    web/
      src/
  infra/
    docker-compose.yml
    openfga/
      model.fga
      seed-tuples.json
    opa/
      policy.rego
  docs/
    architecture.md
    threat-model.md
    api-contracts.md
    attack-scenarios.md
  scripts/