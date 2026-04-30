// GENERATED CODE - DO NOT MODIFY BY HAND

part of 'pending_payment.dart';

// **************************************************************************
// JsonSerializableGenerator
// **************************************************************************

PendingPayment _$PendingPaymentFromJson(Map<String, dynamic> json) =>
    PendingPayment(
      sNo: json['s_no'] as String,
      fprefno: json['fprefno'] as String,
      feesHeads: json['fees_heads'] as String,
      endDate: json['end_date'] as String,
      amount: json['amount'] as String,
      fine: json['fine'] as String,
      totalAmount: json['total_amount'] as String,
      paymentStatus: json['payment_status'] as String,
    );

Map<String, dynamic> _$PendingPaymentToJson(PendingPayment instance) =>
    <String, dynamic>{
      's_no': instance.sNo,
      'fprefno': instance.fprefno,
      'fees_heads': instance.feesHeads,
      'end_date': instance.endDate,
      'amount': instance.amount,
      'fine': instance.fine,
      'total_amount': instance.totalAmount,
      'payment_status': instance.paymentStatus,
    };
