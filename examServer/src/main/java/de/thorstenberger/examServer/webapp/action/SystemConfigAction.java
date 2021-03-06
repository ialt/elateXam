/*

Copyright (C) 2006 Thorsten Berger

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/
/**
 *
 */
package de.thorstenberger.examServer.webapp.action;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.struts.action.ActionForm;
import org.apache.struts.action.ActionForward;
import org.apache.struts.action.ActionMapping;

import de.thorstenberger.examServer.service.ConfigManager;
import de.thorstenberger.examServer.webapp.form.SystemConfigForm;

/**
 * @author Thorsten Berger
 *
 */
public class SystemConfigAction extends BaseAction {

	/* (non-Javadoc)
	 * @see de.thorstenberger.examServer.webapp.action.BaseAction#execute(org.apache.struts.action.ActionMapping, org.apache.struts.action.ActionForm, javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
	@Override
	public ActionForward execute(final ActionMapping mapping, final ActionForm form, final HttpServletRequest request, final HttpServletResponse response) throws Exception {

		final SystemConfigForm scf = (SystemConfigForm)form;
		final ConfigManager configManager = (ConfigManager)getBean( "configManager" );

		scf.setLoadJVMOnStartup( configManager.isLoadJVMOnStartup() );
		scf.setRemoteUserManagerURL( configManager.getRemoteUserManagerURL() );
		scf.setTitle( configManager.getTitle() );
		scf.setHttpAuthURL( configManager.getHTTPAuthURL() );
		scf.setHttpAuthMail( configManager.getHTTPAuthMail() );
    scf.setRadiusHost(configManager.getRadiusHost());
    scf.setRadiusSharedSecret(configManager.getRadiusSharedSecret());
    scf.setSignatureSettings( configManager.getPDFSignatureInfos() );
    
		return mapping.findForward( "systemConfig" );
	}



}
