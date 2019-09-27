<#import "template.ftl" as layout>
<@layout.registrationLayout; section>
    <#if section = "title">
        ${msg("loginTitle",realm.displayName)}
    <#--<#elseif section = "header">
         ${msg("doLogIn")}-->
    <#elseif section = "form">
        <form id="kc-email-code-login-form" class="${properties.kcFormClass!}" action="${url.loginAction}" method="post" style="margin-left: 20px;">
            <div class="${properties.kcFormGroupClass!}">
                <#--div class="form-group">
                                <#--<div-- class="${properties.kcLabelWrapperClass!}">-->

                <#-- </div>-->
                </div-->

                <#--  <div class="${properties.kcInputWrapperClass!}">-->
                <label for="code" class="${properties.kcLabelClass!}" style="margin-bottom: 5px;">${msg("loginEmailOneTime")}</label>
                <input id="code" name="code" type="text" class="${properties.kcInputClass!}" tabindex="2" autofocus placeholder='otp' autocomplete="off" />
                <#--</div>-->
            </div>

            <div class="${properties.kcFormGroupClass!}">
                <#-- <div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
                    <div class="${properties.kcFormOptionsWrapperClass!}">
                    </div>
                </div>-->

                <div id="kc-form-buttons" style="margin-top: 20px;" <#--class="${properties.kcFormButtonsClass!}"-->>
                    <div class="${properties.kcFormButtonsWrapperClass!}">
                        <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonLargeClass!}" name="login" id="kc-login" type="submit" value="submit" style="width: 100%;"/>
                        <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}" name="cancel" id="kc-cancel" type="submit" value="${msg("doCancel")}" style="width: 100%; margin-top: 10px;"/>
                        <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}" name="resend" id="kc-cancel" type="submit" value="resend" style="width: 100%; margin-top: 10px;"/>
                        <#--div class="form-group">
                                                <input class="${properties.kcButtonClass!} ${properties.kcButtonDefaultClass!} ${properties.kcButtonLargeClass!}" name="cancel" id="kc-cancel" type="submit" value="${msg("doCancel")}" style="width: 100%; margin-top: 10px;"/>
                        </div-->
                    </div>
                </div>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
