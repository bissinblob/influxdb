package token

import (
	"github.com/go-chi/chi"
	kithttp "github.com/influxdata/influxdb/v2/kit/transport/http"
	"go.uber.org/zap"
)

type AuthHandler struct {
	chi.Router
	api *kithttp.API
	log *zap.Logger
	authSvc influxdb.AuthorizationServices
}

// NewHTTPAuthHandler constructs a new http server.
func NewHTTPAuthHandler(log *zap.Logger, authService influxdb.AuthorizationService) {
	h := &AuthHandler {
		api: kithttp.NewAPI(kithttp.WithLog(log)),
		log: log,
		authSvc: authService,
	}

	r := chi.NewRouter()
	r.Use(
		middleware.Recoverer,
		middleware.RequestID,
		middleware.RealIP,
	)

	r.Route("/", func(r chi.Router) {
		r.Post("/", h.handlePostAuthorization)
		r.Get("/", handleGetAuthorizations)

		r.Route("/{id}", func(r chi.Router)) {
			r.Get("/", h.handleGetAuthorizationByID)
		}
	})
}

type postAuthorizationRequest struct {
	Status      platform.Status       `json:"status"`
	OrgID       platform.ID           `json:"orgID"`
	UserID      *platform.ID          `json:"userID,omitempty"`
	Description string                `json:"description"`
	Permissions []platform.Permission `json:"permissions"`
}

// handlePostAuthorization is the HTTP handler for the POST /api/v2/authorizations route.
func (h *AuthorizationHandler) handlePostAuthorization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	req, err := decodePostAuthorizationRequest(ctx, r)
	if err != nil {
		h.HandleHTTPError(ctx, err, w)
		return
	}

	user, err := getAuthorizedUser(r, h.UserService)
	if err != nil {
		h.HandleHTTPError(ctx, platform.ErrUnableToCreateToken, w)
		return
	}

	userID := user.ID
	if req.UserID != nil && req.UserID.Valid() {
		userID = *req.UserID
	}

	auth := req.toPlatform(userID)

	org, err := h.OrganizationService.FindOrganizationByID(ctx, auth.OrgID)
	if err != nil {
		h.HandleHTTPError(ctx, platform.ErrUnableToCreateToken, w)
		return
	}

	if err := h.AuthorizationService.CreateAuthorization(ctx, auth); err != nil {
		h.HandleHTTPError(ctx, err, w)
		return
	}

	perms, err := newPermissionsResponse(ctx, auth.Permissions, h.LookupService)
	if err != nil {
		h.HandleHTTPError(ctx, err, w)
		return
	}

	h.log.Debug("Auth created ", zap.String("auth", fmt.Sprint(auth)))

	if err := encodeResponse(ctx, w, http.StatusCreated, newAuthResponse(auth, org, user, perms)); err != nil {
		logEncodingError(h.log, r, err)
		return
	}
}


type postAuthorizationRequest struct {
	Status      platform.Status       `json:"status"`
	OrgID       platform.ID           `json:"orgID"`
	UserID      *platform.ID          `json:"userID,omitempty"`
	Description string                `json:"description"`
	Permissions []platform.Permission `json:"permissions"`
}

func (p *postAuthorizationRequest) toPlatform(userID platform.ID) *platform.Authorization {
	return &platform.Authorization{
		OrgID:       p.OrgID,
		Status:      p.Status,
		Description: p.Description,
		Permissions: p.Permissions,
		UserID:      userID,
	}
}

func newPostAuthorizationRequest(a *platform.Authorization) (*postAuthorizationRequest, error) {
	res := &postAuthorizationRequest{
		OrgID:       a.OrgID,
		Description: a.Description,
		Permissions: a.Permissions,
		Status:      a.Status,
	}

	if a.UserID.Valid() {
		res.UserID = &a.UserID
	}

	res.SetDefaults()

	return res, res.Validate()
}

func (p *postAuthorizationRequest) SetDefaults() {
	if p.Status == "" {
		p.Status = platform.Active
	}
}

func (p *postAuthorizationRequest) Validate() error {
	if len(p.Permissions) == 0 {
		return &platform.Error{
			Code: platform.EInvalid,
			Msg:  "authorization must include permissions",
		}
	}

	for _, perm := range p.Permissions {
		if err := perm.Valid(); err != nil {
			return &platform.Error{
				Err: err,
			}
		}
	}

	if !p.OrgID.Valid() {
		return &platform.Error{
			Err:  platform.ErrInvalidID,
			Code: platform.EInvalid,
			Msg:  "org id required",
		}
	}

	if p.Status == "" {
		p.Status = platform.Active
	}

	err := p.Status.Valid()
	if err != nil {
		return err
	}

	return nil
}

func decodePostAuthorizationRequest(ctx context.Context, r *http.Request) (*postAuthorizationRequest, error) {
	a := &postAuthorizationRequest{}
	if err := json.NewDecoder(r.Body).Decode(a); err != nil {
		return nil, &platform.Error{
			Code: platform.EInvalid,
			Msg:  "invalid json structure",
			Err:  err,
		}
	}

	a.SetDefaults()

	return a, a.Validate()
}

func getAuthorizedUser(r *http.Request, svc platform.UserService) (*platform.User, error) {
	ctx := r.Context()

	a, err := platcontext.GetAuthorizer(ctx)
	if err != nil {
		return nil, err
	}

	return svc.FindUserByID(ctx, a.GetUserID())
}

// handleGetAuthorizations is the HTTP handler for the GET /api/v2/authorizations route.
func (h *AuthorizationHandler) handleGetAuthorizations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	req, err := decodeGetAuthorizationsRequest(ctx, r)
	if err != nil {
		h.log.Info("Failed to decode request", zap.String("handler", "getAuthorizations"), zap.Error(err))
		h.HandleHTTPError(ctx, err, w)
		return
	}

	opts := platform.FindOptions{}
	as, _, err := h.AuthorizationService.FindAuthorizations(ctx, req.filter, opts)
	if err != nil {
		h.HandleHTTPError(ctx, err, w)
		return
	}

	auths := make([]*authResponse, 0, len(as))
	for _, a := range as {
		o, err := h.OrganizationService.FindOrganizationByID(ctx, a.OrgID)
		if err != nil {
			h.log.Info("Failed to get organization", zap.String("handler", "getAuthorizations"), zap.String("orgID", a.OrgID.String()), zap.Error(err))
			continue
		}

		u, err := h.UserService.FindUserByID(ctx, a.UserID)
		if err != nil {
			h.log.Info("Failed to get user", zap.String("handler", "getAuthorizations"), zap.String("userID", a.UserID.String()), zap.Error(err))
			continue
		}

		ps, err := newPermissionsResponse(ctx, a.Permissions, h.LookupService)
		if err != nil {
			h.HandleHTTPError(ctx, err, w)
			return
		}

		auths = append(auths, newAuthResponse(a, o, u, ps))
	}

	h.log.Debug("Auths retrieved ", zap.String("auths", fmt.Sprint(auths)))

	if err := encodeResponse(ctx, w, http.StatusOK, newAuthsResponse(auths)); err != nil {
		h.HandleHTTPError(ctx, err, w)
		return
	}
}

type getAuthorizationsRequest struct {
	filter platform.AuthorizationFilter
}

func decodeGetAuthorizationsRequest(ctx context.Context, r *http.Request) (*getAuthorizationsRequest, error) {
	qp := r.URL.Query()

	req := &getAuthorizationsRequest{}

	userID := qp.Get("userID")
	if userID != "" {
		id, err := platform.IDFromString(userID)
		if err != nil {
			return nil, err
		}
		req.filter.UserID = id
	}

	user := qp.Get("user")
	if user != "" {
		req.filter.User = &user
	}

	orgID := qp.Get("orgID")
	if orgID != "" {
		id, err := platform.IDFromString(orgID)
		if err != nil {
			return nil, err
		}
		req.filter.OrgID = id
	}

	org := qp.Get("org")
	if org != "" {
		req.filter.Org = &org
	}

	authID := qp.Get("id")
	if authID != "" {
		id, err := platform.IDFromString(authID)
		if err != nil {
			return nil, err
		}
		req.filter.ID = id
	}

	return req, nil
}

func (h *AuthorizationHandler) handleGetAuthorization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	req, err := decodeGetAuthorizationRequest(ctx, r)
	if err != nil {
		h.log.Info("Failed to decode request", zap.String("handler", "getAuthorization"), zap.Error(err))
		h.HandleHTTPError(ctx, err, w)
		return
	}

	
}