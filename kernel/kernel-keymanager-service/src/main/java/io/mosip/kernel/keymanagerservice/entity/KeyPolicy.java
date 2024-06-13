package io.mosip.kernel.keymanagerservice.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

/**
 * Entity class for KeyPolicy
 * 
 * @author Dharmesh Khandelwal
 * @since 1.0.0
 *
 */
@Entity
@Table(name = "key_policy_def")
@Data
@EqualsAndHashCode(callSuper = false)
@NoArgsConstructor
@AllArgsConstructor
public class KeyPolicy extends BaseEntity {

	/**
	 * The field applicationId
	 */
	@Id
	@Column(name = "app_id", nullable = false, length = 36)
	private String applicationId;

	/**
	 * The field validityInDays
	 */
	@Column(name = "key_validity_duration")
	private int validityInDays;

	/**
	 * The field isActive
	 */
	@Column(name = "is_active")
	private boolean isActive;

	/**
	 * The field Pre Expire Days
	 */
	@Column(name = "pre_expire_days")
	private int preExpireDays;

	/**
	 * The field access allowed
	 */
	@Column(name = "access_allowed")
	private String accessAllowed;
}
