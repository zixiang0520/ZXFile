package controllers

import (
	"github.com/cloudreve/Cloudreve/v4/service/vas"
	"github.com/gin-gonic/gin"
)

// VASCreatePayment creates a purchase order.
func VASCreatePayment(c *gin.Context) {
	service := &vas.CreatePaymentRequest{}
	res := service.Create(c)
	c.JSON(200, res)
}

// VASPaymentStatus polls an order's status.
func VASPaymentStatus(c *gin.Context) {
	res := vas.PaymentStatus(c)
	c.JSON(200, res)
}

// VASListSKUs returns shop SKUs.
func VASListSKUs(c *gin.Context) {
	res := vas.ListSKUs(c)
	c.JSON(200, res)
}

// VASRedeemGiftCode redeems a gift code.
func VASRedeemGiftCode(c *gin.Context) {
	res := vas.Redeem(c)
	c.JSON(200, res)
}

// VASGetPoints returns the user's points balance + history.
func VASGetPoints(c *gin.Context) {
	res := vas.PointsSummary(c)
	c.JSON(200, res)
}

// VASListMyPayments lists the user's orders.
func VASListMyPayments(c *gin.Context) {
	res := vas.ListMyPayments(c)
	c.JSON(200, res)
}

// VASEpayNotify handles epay async notifications.
func VASEpayNotify(c *gin.Context) {
	vas.EpayNotify(c, c.Param("pid"))
}

// VASCustomNotify handles custom gateway notifications.
func VASCustomNotify(c *gin.Context) {
	vas.CustomNotify(c, c.Param("pid"))
}

// VASAdminListPayments lists all payments.
func VASAdminListPayments(c *gin.Context) {
	res := vas.AdminListPayments(c)
	c.JSON(200, res)
}

// VASAdminDeletePayments batch deletes payments.
func VASAdminDeletePayments(c *gin.Context) {
	service := ParametersFromContext[*vas.AdminDeletePaymentsService](c, vas.AdminDeletePaymentsParamCtx{})
	res := service.Delete(c)
	c.JSON(200, res)
}

// VASSaveSKUs persists the SKU list.
func VASSaveSKUs(c *gin.Context) {
	service := ParametersFromContext[*vas.SaveSKUsService](c, vas.SaveSKUsParamCtx{})
	res := service.Save(c)
	c.JSON(200, res)
}

// VASListProviders returns payment providers.
func VASListProviders(c *gin.Context) {
	res := vas.ListProviders(c)
	c.JSON(200, res)
}

// VASSaveProviders persists payment providers.
func VASSaveProviders(c *gin.Context) {
	service := ParametersFromContext[*vas.SaveProvidersService](c, vas.SaveProvidersParamCtx{})
	res := service.Save(c)
	c.JSON(200, res)
}

// VASAdminCreateGiftCodes generates gift codes.
func VASAdminCreateGiftCodes(c *gin.Context) {
	res := vas.AdminCreateGiftCodes(c)
	c.JSON(200, res)
}

// VASAdminListGiftCodes lists gift codes.
func VASAdminListGiftCodes(c *gin.Context) {
	res := vas.AdminListGiftCodes(c)
	c.JSON(200, res)
}

// VASAdminDeleteGiftCodes batch deletes gift codes.
func VASAdminDeleteGiftCodes(c *gin.Context) {
	service := ParametersFromContext[*vas.AdminDeleteGiftCodesService](c, vas.AdminDeleteGiftCodesParamCtx{})
	res := service.Delete(c)
	c.JSON(200, res)
}
