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
package de.thorstenberger.examServer.model;

import java.util.List;

/**
 * @author Thorsten Berger
 *
 */
public class TaskletVO {

	private long id;
	private String login;
	private long taskDefId;
	private String status;
	private Float autoCorrectionPoints;

	private List<ManualCorrectionsVO> manualCorrections;
	
	private List<CorrectorTaskletAnnotationVO> correctorAnnotations;
	private List<StudentTaskletAnnotationVO> studentAnnotations;
	
	private String correctorLogin;
	private List<String> correctorHistory;
	private List<String> flags;
	
	
	/**
	 * @return the manualCorrections
	 */
	public List<ManualCorrectionsVO> getManualCorrections() {
		return manualCorrections;
	}
	/**
	 * @param manualCorrections the manualCorrections to set
	 */
	public void setManualCorrections(List<ManualCorrectionsVO> manualCorrections) {
		this.manualCorrections = manualCorrections;
	}
	/**
	 * @return Returns the flags.
	 */
	public List<String> getFlags() {
		return flags;
	}
	/**
	 * @param flags The flags to set.
	 */
	public void setFlags(List<String> flags) {
		this.flags = flags;
	}
	/**
	 * @return Returns the correctorAnnotations.
	 */
	public List<CorrectorTaskletAnnotationVO> getCorrectorAnnotations() {
		return correctorAnnotations;
	}
	/**
	 * @param correctorAnnotations The correctorAnnotations to set.
	 */
	public void setCorrectorAnnotations(
			List<CorrectorTaskletAnnotationVO> correctorAnnotations) {
		this.correctorAnnotations = correctorAnnotations;
	}
	/**
	 * @return Returns the studentAnnotations.
	 */
	public List<StudentTaskletAnnotationVO> getStudentAnnotations() {
		return studentAnnotations;
	}
	/**
	 * @param studentAnnotations The studentAnnotations to set.
	 */
	public void setStudentAnnotations(List<StudentTaskletAnnotationVO> studentAnnotations) {
		this.studentAnnotations = studentAnnotations;
	}
	/**
	 * @return Returns the correctorHistory.
	 */
	public List<String> getCorrectorHistory() {
		return correctorHistory;
	}
	/**
	 * @param correctorHistory The correctorHistory to set.
	 */
	public void setCorrectorHistory(List<String> correctorHistory) {
		this.correctorHistory = correctorHistory;
	}
	/**
	 * @return Returns the correctorLogin.
	 */
	public String getCorrectorLogin() {
		return correctorLogin;
	}
	/**
	 * @param correctorLogin The correctorLogin to set.
	 */
	public void setCorrectorLogin(String correctorLogin) {
		this.correctorLogin = correctorLogin;
	}
	/**
	 * @return Returns the id.
	 */
	public long getId() {
		return id;
	}
	/**
	 * @param id The id to set.
	 */
	public void setId(long id) {
		this.id = id;
	}
	/**
	 * @return Returns the login.
	 */
	public String getLogin() {
		return login;
	}
	/**
	 * @param login The login to set.
	 */
	public void setLogin(String login) {
		this.login = login;
	}
	/**
	 * @return Returns the autoCorrectionPoints.
	 */
	public Float getAutoCorrectionPoints() {
		return autoCorrectionPoints;
	}
	/**
	 * @param points The autoCorrectionPoints to set.
	 */
	public void setAutoCorrectionPoints(Float points) {
		this.autoCorrectionPoints = points;
	}
	/**
	 * @return Returns the status.
	 */
	public String getStatus() {
		return status;
	}
	/**
	 * @param status The status to set.
	 */
	public void setStatus(String status) {
		this.status = status;
	}
	/**
	 * @return Returns the taskDefId.
	 */
	public long getTaskDefId() {
		return taskDefId;
	}
	/**
	 * @param taskDefId The taskDefId to set.
	 */
	public void setTaskDefId(long taskDefId) {
		this.taskDefId = taskDefId;
	}
	
	public class ManualCorrectionsVO{
		private String corrector;
		private float points;
		/**
		 * @param corrector
		 * @param points
		 */
		public ManualCorrectionsVO(String corrector, float points) {
			super();
			this.corrector = corrector;
			this.points = points;
		}
		/**
		 * @return the corrector
		 */
		public String getCorrector() {
			return corrector;
		}
		/**
		 * @param corrector the corrector to set
		 */
		public void setCorrector(String corrector) {
			this.corrector = corrector;
		}
		/**
		 * @return the points
		 */
		public float getPoints() {
			return points;
		}
		/**
		 * @param points the points to set
		 */
		public void setPoints(float points) {
			this.points = points;
		}
		
	}
	

}
